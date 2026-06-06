# Recent Changes Log

## 2026-06-06 — CPU power retune and RAM/I/O subsystem cleanup

- **Realistic scalar unchanged**: `RunRealisticCompilerSim_V3` was left untouched and is now pinned by a source-hash invariant test.
- **Synthetic scalar retuned**: Active synthetic buffer is now 64 KiB (`SYNTH_WORK_BUF_ELEMS = 8192`). Hot-loop vector div/sqrt and integer division were removed. x86 SSE2 split mul/add uses a local no-contract barrier (`Sse2SplitMulAddNoContract`) so `-ffast-math` cannot silently contract it to FMA; integer side now uses `MixGpr()` multiply/rotate/xor chains plus modest shuffle pressure.
- **AVX2/AVX-512 retuned**: AVX2 keeps 16 YMM accumulators and AVX-512 keeps 32 ZMM accumulators, but vector div/sqrt are removed. Both use memory FMA plus a small in-register FMA+permute/shuffle slice. Temporary Windows v3 assembly check found zero `vdivpd`/`vsqrtpd`, with FMA and permutes present; shuffle count was reduced after an initial attempt produced excessive stack moves.
- **`--perf-stats` fixed**: CPU feature detection and FPU flush mode are initialized before timing, so AVX-512 gating and FP state match normal execution.
- **RAM stress fixed**: 1.5 GiB cap retained, but streaming now touches the full allocation instead of the rounded-down power-of-two subset. Pointer chasing has a separate power-of-two chase count/mask, Linux initialization fills actual chase entries, active allocations are reused across bursts, and activation logging records effective bytes and the 90% stream / 10% chase ratio.
- **I/O stress fixed**: Windows and Unix read paths share `HashIoBufferForCpuPower()`. AVX2 CPU-side hashing now uses four independent vector accumulators plus scalar final mixing. I/O thread policy remains `min(cpu/4, 8)` with startup/open-failure logging.
- **Tests updated**: Invariants now assert the new no-div/sqrt contract, SSE no-contract helper, FMA+permute/shuffle mix, RAM stream/chase separation, shared I/O hash helper, and `--perf-stats` initialization. `--stress` coverage now includes a short AVX2 repro when available.

## 2026-06-04 — Replace LHM EXE with extracted PawnIO_setup.exe

- **PawnIO_setup.exe extracted at build time**: `build.py` extracts `PawnIO_setup.exe` from LHM's embedded .NET resources during build. Eliminates `LibreHardwareMonitor.exe` (4.3 MB) from lhm/, replaced by standalone `PawnIO_setup.exe` (3.1 MB).
- **Simplified InstallPawnIO()**: No more PowerShell extraction at runtime. C++ just runs `PawnIO_setup.exe -install -silent` directly.
- **PawnIO scripts updated**: Both scripts use standalone `PawnIO_setup.exe`, auto-verify results, no user confirmation needed.
- **LHM folder final size**: 11 files — `PowerReader.exe`, `PowerReader.exe.config`, `LibreHardwareMonitorLib.dll`, `PawnIO_setup.exe`, 3x System.*.dll, 2x scripts, 2x license files.
- **44/44 tests pass**.

## 2026-06-04 — Replace WMI with PowerReader.exe (C# helper, compiled at build)

- **Root cause found**: LHM's WMI provider is broken. Registration shows version 0.9.2.0 but library is 0.9.6.0 — version mismatch prevents WMI host from loading the provider. Namespace `root\OpenHardwareMonitor` exists but has 0 sensor instances. This was never going to work.
- **New approach**: `vendor/lhm/PowerReader.cs` — a small C# helper EXE compiled at build time via `csc.exe`. Loads `LibreHardwareMonitorLib.dll` directly, reads the Package power sensor, outputs watts to stdout. Needs .NET 4.8 app.config for `MutexSecurity` constructor.
- **C++ integration**: `SampleCpuPackagePower()` launches `PowerReader.exe` via `CreateProcess` + stdout pipe. Working directory set to `lhm/` so all .NET dependencies are found. 3-second cache to avoid excessive process spawns.
- **Removed**: All WMI code (`IWbemLocator`, `IWbemServices`, `ConnectWmi`, `StartLHM`, `IEnumWbemClassObject`). Removed `-lwbemuuid` linker flag.
- **Kept**: PawnIO auto-install (registry check + extract from LHM embedded resources).
- **Build**: `build.py` compiles `PowerReader.cs` with `csc.exe /platform:x64`, writes `.NET 4.8` app.config.
- **Tested**: PowerReader.exe outputs 42.8 W on AMD Ryzen 7 5700X (admin required).
- **Verification**: 44/44 tests pass. `python build.py native` clean.

## 2026-06-04 — Auto-install PawnIO before LHM, remove dialog watcher

- **PawnIO auto-install**: Before starting LHM, check registry for PawnIO. If missing, extract `PawnIO_setup.exe` from LHM's embedded .NET resources via PowerShell, run `-install` silently, clean up. No user interaction needed.
- **Dialog watcher removed**: PawnIO is now installed before LHM starts, so the PawnIO dialog never appears.
- **Extended WMI polling**: 20 seconds (was 8s) with LHM process liveness checks during polling.
- **Root cause**: LHM's WMI provider (`root\librehardwaremonitor`) requires PawnIO to register. Without PawnIO, WMI returns `0x8004100E` (namespace not found). The previous approach of launching LHM and hoping WMI works was flawed.
- **Files changed**: `Workloads.cpp`
- **Verification**: 44/44 tests pass.

## 2026-06-04 — LHM debug logging + PawnIO dialog suppression

- **Debug logging**: Added comprehensive logging to `StartLHM()`, `ConnectWmi()`, `InitPowerMeasurement()` — all output to `ShaderStress.log` with process start, WMI connection status, sensor detection result.
- **PawnIO dialog fix**: Added `DialogWatcherThread` using `EnumWindows` to find and `WM_CLOSE` the PawnIO install dialog that LHM shows on first run. `SW_HIDE` only hides the main form, not the `MessageBox` dialog. Thread runs for up to 10s after LHM launch.
- **Root cause of no power logging**: LHM requires PawnIO driver to read RAPL MSRs. Without PawnIO, the WMI namespace has no Power sensors, so `SampleCpuPackagePower()` returns -1.0. The dialog watcher at least prevents the blocking dialog; actual power reading still requires PawnIO to be installed.
- **Files changed**: `Workloads.cpp`
- **Verification**: 44/44 tests pass.

## 2026-06-04 — Slim down LHM integration, fix power logging, add cleanup

- **LHM bin spam fix**: Moved LHM files to `bin/<target>/lhm/` subfolder instead of flat alongside ShaderStress binaries. Updated `build.py` copy destination and `StartLHM()` path in `Workloads.cpp`.
- **Power logging to file**: Added periodic power logging (every ~5s) to `ShaderStress.log` during benchmarks via Watchdog thread. Added power to benchmark completion report (`LogRaw`). Added power to final results log entry (`PrintFinalResults`).
- **LHM process cleanup**: Added `ShutdownPowerMeasurement()` — terminates the LHM process and releases COM on exit. Called from `CleanupWorkers()`.
- **Tests**: 4 new invariant tests verifying LHM subfolder path, build copy target, shutdown function presence, and power logging.
- **Files changed**: `build.py`, `Workloads.cpp`, `Common.h`, `Threading.cpp`, `ShaderStress.cpp`, `tests/run_tests.py`, `llm-wiki/overview.md`
- **Verification**: 44/44 tests pass (34 CLI + 4 workload + 2 golden + 2 UBSan + 4 new invariants). `python build.py native` clean.

## 2026-06-04 — Power-draw inversion: cache residency + expensive compute ops

**Inverts the 2026-05-23 "L2-miss memory controller" design** — per user note, data staying in CPU caches yields higher package power than data spilling to DRAM (cache hits keep execution units busy; DRAM access stalls the pipeline).

- **Workloads.cpp — buffer size**: `WORK_BUF_ELEMS` 65536 → 32768 (512 KB → 256 KB, L2-resident on all modern CPUs). Reverts 2026-05-23's deliberate L2-miss design.
- **Workloads.cpp — AVX-512**: Replaced 4 of 32 FMA WORK calls with `_mm512_div_pd` and 4 with `_mm512_sqrt_pd`. Feeds the otherwise-idle div/sqrt execution unit. GPR chains 8 → 16 (g0–g15) for more integer-pipe pressure.
- **Workloads.cpp — AVX-2**: Replaced 1 of 16 FMA with `_mm256_div_pd` and 1 with `_mm256_sqrt_pd`. GPR chains 8 → 16.
- **Workloads.cpp — SSE2**: Replaced 1 of 48 split-mul-add WORK calls with `_mm_div_pd` and 1 with `_mm_sqrt_pd`.
- **Workloads.cpp — NEON (ARM64)**: Replaced 2 of 48 NEON_WORK with `vdivq_f64` and 2 with `vsqrtq_f64`.
- **Workloads.cpp — function attributes**: Added `__attribute__((hot))` to `TARGET_AVX2` and `TARGET_AVX512` for icache priority (no µop-cache bloat risk).
- **Threading.cpp — DecompressLogic**: `PASSES` 128 → 256; added 64-bit `idiv` every 64 bytes (high-latency port-0 traffic, ~20-40 cycles each).
- **Threading.cpp — IOThread (Windows + Linux)**: Added a 2nd-pass AVX2 hash on the 256 KB read buffer (gated on `__AVX2__`). Doubles per-read CPU burst on the IO core.
- **Common.h + Threading.cpp — RAMThread**: New `RAM_STRESS_MAX_BYTES = 1536 MiB` (1.5 GB) constant. Caps the working set to 1.5 GB (L3-friendly). Replaces "70 % of available memory, max 16 GB" which put heavy load on DRAM subsystem.
- **tests/run_tests.py — 10 new read-only invariant tests**:
  - `test_invariant_work_buf_elems` (256 KB)
  - `test_invariant_ram_stress_cap` (1.5 GB)
  - `test_invariant_decomp_passes` (256)
  - `test_invariant_avx512_vec_div` / `_vec_sqrt` (AVX-512 div/sqrt)
  - `test_invariant_avx2_vec_div` (AVX-2 div)
  - `test_invariant_sse2_vec_div` (SSE2 div)
  - `test_invariant_io_avx2_hash` (2nd-pass AVX2 hash in IOThread)
  - `test_invariant_decomp_idiv` (64-bit IDIV every 64 bytes)
  - `test_invariant_realistic_unchanged` (RunRealisticCompilerSim_V3 byte-identical)
- **Verification**: 38/38 tests pass (20 CLI + 10 invariant + 4 stress + 2 golden + 2 UBSan). `python build.py native` builds clean.
- **Explicitly NOT touched**: `RunRealisticCompilerSim_V3` (user-excluded), `tests/golden_values.json` (unchanged), `build.py` flags (current set is correct: no unroll/peel/web/cf-protection per the 2026-05-23 design).

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
