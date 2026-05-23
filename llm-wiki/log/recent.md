# Recent Changes Log

## 2026-05-23 — v2: Strip extra optimization flags, add --perf-stats

- **build.py**: Removed `-frename-registers`, `-fweb`, `-funroll-all-loops`, `-fpeel-loops`, `-fcf-protection=full`. These made code too efficient (fewer cycles/iter), reducing sustained power draw. Online release uses vanilla `-O3`.
- **New `--perf-stats` command**: Runs each workload with RDTSC cycle counting and prints cycles/iteration. Useful for diagnosing stall sources without external tools.
- **Wiki updated**: opt-audit.md documents removed flags.

## 2026-05-23 — Reverted workload over-optimization; matched proven online design for max power

- **Root cause**: Previous pure reg-reg pivot (SSE2/NEON) and L1-traffic additions (AVX2) empirically REDUCED power draw vs the online GitHub release. Analysis revealed that: (1) removing memory WORK calls left load/store ports (2/3/4) underutilized, (2) adding shuffles/FMAs bloated the loop body causing µop cache pressure, (3) replacing integer division with multiply-XOR reduced pipeline backpressure.
- **SSE2/Scalar**: Reverted to 48 WORK calls (3 passes × 16) using split `_mm_mul_pd + _mm_add_pd` (not FMA) for double µop count. Integer division for sustained pipeline backpressure. Buffer: 512KB (up from 256KB) to cause L2 misses → memory controller activity. Removed all shuffles and reg-reg FMAs. Iteration count: `complexity * 200` → `*280`.
- **NEON (ARM64)**: Same 48-WORK design with NEON intrinsics, IDIV on GPRs.
- **AVX2**: Reverted to 8 WORK calls with FMA (`_mm256_fmadd_pd`), 8 GPRs with multiply-XOR chains, removed all permutes and reg-reg FMAs. 512KB buffer.
- **AVX-512**: Reverted to 32 WORK calls on all 32 ZMM registers, 8 GPRs with multiply-XOR chains. Removed mask ops, shuffles, and extra FMAs.
- **All tests pass**: 28/28 (20 CLI + 4 stress + 2 golden + 2 UBSan) on x64 baseline and v3 builds.

## 2026-05-22 — Code quality sweep: UB fixes, security hardening, binary quality, test expansion

- **F-01-001 (Critical)**: Fixed efficiency class inversion on Windows hybrid CPUs. `effClass == 0` was mapped to P-core (should be E-core), causing workers to run on slow cores on Intel Alder Lake+ / AMD hybrid systems. Swapped pCoreLps/eCoreLps in `BuildHybridCpuMap` (Platform.cpp) and `EnumerateHybridTopology` (CpuFeatures.cpp). Higher efficiency class = more performant core per Intel/AMD docs.
- **F-02-002 (High)**: Fixed default opcode rotate in `RunRealisticCompilerSim_V3`. Was using 32-bit shift amounts (`src2 & 31`, `32 - (src2 & 31)`) on 64-bit values. Now uses 64-bit (`src2 & 63`, `64 - (src2 & 63)`). All golden values regenerated.
- **F-03-003 (High)**: Fixed predictable temp file paths in IOThread. Added random suffix to filenames to prevent symlink attacks. Windows uses `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_FLAG_DELETE_ON_CLOSE`. Linux uses `O_NOFOLLOW` and `O_CREAT | O_EXCL`.
- **F-04-004 (High)**: Fixed UB from interleaving `std::cout` and `std::wcout`. Converted all output to narrow `std::cout` with `ToNarrow()` helper. Removed all `std::wcout`/`std::wcerr` calls from ShaderStress.cpp.
- **F-05-005 (High)**: Fixed strict-aliasing violation in `GetCpuBrand` (CpuFeatures.cpp). Replaced `unsigned int*` pointer cast with `unsigned int buf[12]` + `std::memcpy`.
- **F-06-006 (High)**: Fixed signed integer overflow in workload complexity multipliers. All 4 `int iters = complexity * N` now use `(int)std::min<uint64_t>((uint64_t)complexity * Nu, 2000000000u)`.
- **F-08-008 (Medium)**: Fixed Linux hybrid pinning no-op ternary in `PinThreadToCore`. Now maps `coreIdx < numPcores` to P-cores, remaining to E-cores.
- **F-09-009 (Medium)**: Moved `SetConsoleCtrlHandler` registration before thread creation to close Ctrl+C race window.
- **F-10-010/F-14-014 (Medium)**: Fixed cli_launcher.c NULL deref when filename has no `.com` extension. Added graceful `.exe` append fallback. Reverted `bInheritHandles=FALSE` change (breaks console output for GUI-subsystem .exe).
- **F-12-012 (Medium)**: Added workload regression tests: `test_repro_scalar_quick`, `test_repro_scalar_sim_quick`, `test_repro_high_complexity` (boundary test near overflow threshold).
- **F-13-013 (Medium)**: Added `--sanitize`, `--sanitize=address`, `--sanitize=thread` flags to build.py for development UBSan/ASan/TSan builds.
- **Build verification**: 4/4 Windows targets build clean, 25/25 tests pass (19 CLI + 4 stress + 2 golden value) on x64 baseline and v3. v4 = STATUS_ILLEGAL_INSTRUCTION on non-AVX-512 CPU (expected).

## 2026-05-22 — Windows builds switched from Zig to LLVM MinGW

- **Windows compiler replaced**: All Windows build targets now use LLVM MinGW 20260519 (LLVM 22.1.6, UCRT) via mstorsjo/llvm-mingw instead of `zig c++`.
- **build.py restructured**: `build_target()` now dispatches to `build_windows_target()` (LLVM MinGW, `clang++`/`lld`) or `build_zig_target()` (Zig, Linux/macOS).
- **Flag translation**: Zig `-mcpu=x86_64_v3` → Clang `-march=x86-64-v3`; Zig `-Xlinker` pairs → Clang `-Wl,` flags; `zig rc` → `llvm-windres`.
- **New toolchain**: `llvm-mingw-20260519-ucrt-x86_64/` with `x86_64-w64-mingw32-clang++.exe`, `aarch64-w64-mingw32-clang++.exe`, `llvm-windres.exe`.
- **Output dirs renamed**: `bin/x64-zig*` → `bin/x64-llvm*`, `bin/arm64-zig` → `bin/arm64-llvm`.
- **Archive names shortened**: Removed `-Zig` suffix from Windows archives.
- **tests/run_tests.py**: Updated binary search paths to `bin/x64-llvm*`.
- **Zig retained** for Linux/macOS cross-compilation.

## 2026-05-14 — AVX2 workload switched from mixed memory+compute to pure reg-reg

- **AVX2 hot loop redesigned**: Replaced the previous V6-style 256KB buffer workload (16 WORK calls, load+FMA+store per iteration) with a pure reg-reg design: zero memory traffic in the hot loop. Buffer is now only used for initial seeding and remains untouched during the stress loop.
- **New hot loop composition**: 48 FMAs (3 rotations of 16 daisy-chained FMAs), 48 permutes (3 rotations of 16 cross-lane shuffles), and 16 GPR chains (g0–g15). No idx, no stride, no prefetch, no WORK macro.
- **Rationale**: On Zen 3, the previous memory-heavy workload had lower power draw than the scalar synthetic workload. Root cause analysis suggests memory pipeline stalls caused FMA ports (0/1) to be underutilized, and/or the mixed memory+compute pattern didn't compensate for AVX2 frequency reduction on Zen 3. Pure reg-reg eliminates all memory-induced stalls for maximum sustained FMA throughput.

## 2026-05-14 — Removed AVX2 V0–V5 workload variants; single unified AVX2 workload

- **AVX2 V0–V5 eliminated**: All variant infrastructure (`AVX2_VARIANT`, `MASK_AVX2_V*`, `WORK_BUF_ELEMS_V*`) removed from codebase and build system.
- **build.py cleaned up**: No variant build targets, no AVX2_VARIANT preprocessor switching. 10 clean targets.
- **Single unified AVX2 workload**: `RunHyperStress_AVX2` now always runs the optimal configuration — 256KB buffer (32768 doubles, guaranteed L2 residency on Zen 3), 16 WORK calls (single memory pass, no load/store port saturation), 16 GPR chains (g0–g15, golden-ratio multiply-XOR), 32 permutes (16+16, saturates port 5), 32 daisy-chain FMAs (16+16, saturates ports 0/1). This was previously the V6 variant; all other variants (reg-reg-only V5, V4, etc.) removed as inferior.
- **`MASK_AVX2` and `WORK_BUF_ELEMS`**: Only one constant each; `MASK_AVX2 = (WORK_BUF_ELEMS - 4)` with `WORK_BUF_ELEMS = 32768`.

## 2026-05-14 — Major CPU power draw increase across all workload types

- **New V5 variant (AVX2)**: Pure reg-reg FMA + shuffle, zero memory ops. 16 GPR chains, 32 permutes, 32 daisy-chain FMAs. Eliminates all memory-induced stalls for maximum sustained FMA throughput.
- **New V6 variant (AVX2)**: 256KB buffer (half size, guaranteed L2 residency on Zen 3). 16 WORK + 16 GPR chains + 32 permutes + 32 FMAs. Added `MASK_AVX2_V6`, `WORK_BUF_ELEMS_V6` constants.
- **SSE2/Scalar overhaul**: Reduced WORK from 48 → 16 (single pass instead of 3, fixes load/store pipeline saturation). Doubled reg-reg FMA 16→32, shuffles 16→32, GPR chains 8→16 (g0–g15 all used). Stride reduced 96→64.
- **Preprocessor gating**: V5/V6 included in daisy-chain and permute blocks across all ISA paths.
- **I/O thread**: Replaced trivial `volatile uint8_t sink` with full buffer integer hash (FNV-1a-like multiply-XOR chain) on both Windows and Linux paths — keeps CPU cores hot while stressing storage.
- **RAM thread**: Replaced trivial `p[i] = (i+16) % count` / `p[i] = p[i] + 1` with 4-accumulator integer multiply-chain (read, hash, write-back in groups of 4) on both paths.
- **Decompression thread**: BUF_SIZE 512KB→256KB, PASSES 64→128, added `acc = (acc * 0x9E3779B97F4A7C15ULL) ^ (acc >> 31)` integer multiply targeting port 0 on Zen 3.
- **Linux IOThread/RAMThread**: Added missing `DisablePowerThrottling()` calls.
- **build.py**: Help text updated for avx2-5 and avx2-6; variant range comments 0–4→0–6.

## 2026-05-13 — Fix: decomp threads starved + underpowered + CPU underutilization

- **Bugfix**: Three issues in steady/dynamic mode threading. (1) IO threads counted against worker budget despite being I/O-bound — only 8 CPU-bound comp threads on 16t CPU. Changed `reserved` to count only RAM (1 slot), so available=15 workers. (2) Clamping starved decomp when over budget. Fixed with proportional split. (3) `RunDecompressLogic` did only one 512KB pass per invocation (~microseconds), too lightweight. Added 64-pass loop so each call does meaningful work matching compiler workload duration.

## 2026-05-13 — Optimization Audit v3 (Execution Port Saturation Sweep)

- **Build**: Added `-funroll-all-loops`, `-fpeel-loops` (aggressive unrolling + alignment)
- **Build**: Added `-mprefer-vector-width=512` for x86_64_v4 targets (forces ZMM in auto-vec)
- **Build**: Added `--pgo-gen` / `--pgo-use` flags for PGO workflow (build.py)
- **Code**: Port 5 shuffle pressure — `_mm_shuffle_pd` / `_mm256_permute4x64_pd` / `_mm512_permutex_pd` / `vextq_f64` in all max-power hot loops, saturating the otherwise-idle shuffle port
- **Code**: AVX-512 mask register pressure — `_mm512_cmp_pd_mask` + `_mm512_mask_blend_pd` in AVX-512 hot loop
- **Code**: Replaced integer `idiv` with `multiply+xor+shift` in SSE2/NEON max-power paths (eliminates ~40-cycle pipeline stalls from each idiv, keeps FMA pipes saturated)
- **Code**: Cross-lane shuffle+add at function exit reduction in all 4 workloads
- **Code**: More IO threads: 4 → 8 (Threading.cpp, Workloads.cpp cleanup)
- **Code**: Thread affinity re-assertion every 10s in WorkerThread to prevent OS migration
- **Skipped**: Cache-thrashing approaches (reduces CPU power by stalling execution), NT stores (bypass cache → less CPU-side power), random access patterns (stalls → less power)

## 2026-05-12 — Optimization Audit v2 (Missing Optimization Sweep)

- **Build**: Added `-fno-exceptions` (removes all EH tables, zero risk — no try/catch/throwing code)
- **Build**: Added `-fno-semantic-interposition` (more aggressive inlining with LTO)
- **Build**: Added `--gc-sections` to Linux linker flags (removes dead sections)
- **Platform**: Windows PowerRequest API — `PowerCreateRequest` + `PowerSetRequest(ExecutionRequired)` prevents frequency reduction, core parking, deep C-states. Process-scoped, no system-wide change.
- **Platform**: Hybrid P-core pinning — `EnumerateHybridTopology()` via `GetLogicalProcessorInformationEx` (Windows) fills `numPcores`/`numEcores`. `PinThreadToCore` maps workers to P-cores first.
- **Platform**: Linux `energy_performance_preference = 'performance'` sysfs write (often writable without root)
- **Platform**: Linux `mlock()` in `ScopedMem` — prevents RAM page swapping during stress
- **Code**: `[[unlikely]]` annotations on all 4 workload quit checks + thread loop terminate checks
- **Code**: RAM stress stride reduced from 64→1, ratio changed 50/50→70/30 (more bandwidth saturation)
- **Code**: AppState false sharing fix — 4 cache-line-aligned groups prevent MESI bouncing
- **Code**: Multi-thread IO stress — up to `min(cpu/4, 4)` IO threads with separate files
- **Code**: Replaced `std::locale::global` + try/catch with `std::setlocale` (enables `-fno-exceptions`)
- **Skipped/Rejected**: Thread/process priority changes (can freeze OS), PGO (complex),
  macOS LTO (needs investigation), Windows power scheme (replaced by PowerRequest)

## 2026-05-12 — Optimization Audit v1

- **Build**: Added x86_64_v4 targets (AVX-512 baseline) for Windows and Linux
- **Build**: Added `-frename-registers`, `-fweb`, `-fno-stack-protector`, `-fomit-frame-pointer`, Linux linker sort flags
- **Build**: Native target now prefers highest CPU variant (v4 > v3 > baseline)
- **Platform**: Linux power management — sets scaling governor to 'performance' via sysfs
- **Platform**: Hybrid CPU topology detection in CpuFeatures (isHybrid flag)
- **Code**: SSE2 scalar path uses `_mm_fmadd_pd` when `__FMA__` is defined (v3/v4 builds)
- **Code**: Prefetch distance doubled (2 strides ahead) for all workload paths
- **Code**: Replaced all `std::stoull`/`std::stoll`/`std::stoi` with noexcept `std::from_chars`
- **llm-wiki**: Created initial wiki pages (index, overview, opt-audit, log)
