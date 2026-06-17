# Optimization Audit

Audited for maximum power draw, throughput, heat, and utilization (initial audit 2026-05-14; latest redesign 2026-06-13).

**2026-06-17 — CPU power draw improvements (current)**: IO/RAM/decompression subsytems and AVX2/AVX-512 synthetic kernels received additional execution-unit pressure. IO thread now runs a full-buffer multiply-XOR hash instead of a minimal sink. RAM thread's write-stride pass uses a 4-accumulator integer multiply chain. Decompression tripled its 64-bit IDIV density (3 IDIV per 64 bytes instead of 1). AVX2 and AVX-512 GPR chains expanded from 8→16 registers. AVX2 gained 4 `_mm256_permute4x64_pd` ops per iteration (port-5 pressure). AVX-512 gained 4 `_mm512_permutex_pd` + `_mm512_cmp_pd_mask` / `_mm512_mask_blend_pd` (port-5 + mask register pressure). `-funroll-loops` and `-fno-strict-aliasing` restored on both LLVM MinGW and Zig paths, with `-nounroll` variants available for comparison (`win-v3-nounroll`, `zig-v3-nounroll`).

**2026-06-13 — Upstream-style power redesign (superseded)**: Measured package power on a PBO-unlocked Ryzen 5700X was higher with the upstream GitHub profile than with the local L1-resident/sparse-store design. Reverted the synthetic kernels to the upstream profile: 65536 doubles/thread (512 KiB) working sets, store-every-result, and 64-bit GPR integer division in scalar/SSE2/NEON hot loops. RAM stress returned to 70 % of available physical RAM capped at 16 GiB. IO stress reverted to a single thread with a minimal CPU sink so heavy synthetic kernels keep cores. Added Zig Windows build targets to match the GitHub release toolchain. Restored the `hot` function attribute on synthetic kernels. Removed `-funroll-loops` and `-fno-strict-aliasing` from the LLVM MinGW path (they reduced realistic-workload power with that toolchain) while keeping them on the Zig path. Removed defensive security hardening from `RunRealisticCompilerSim_V3` (string-table bounds check) and `IOThread` (symlink/TOCTOU/random-filename checks) that sacrificed power. Removed the 10-second worker thread affinity re-assertion. `RunRealisticCompilerSim_V3` source hash baseline was updated; decompression keeps its local IDIV-heavy 256-pass design.

**2026-06-07 — L1-resident, store-light, dual-cluster redesign (superseded)**: Superseded by the 2026-06-13 upstream-style redesign. The remaining ~25-30 W gap on a PBO-unlocked Ryzen 5700X was structural: the 64 KiB/thread active set was L2- not L1-resident, and storing every WORK result made the single store port the loop bottleneck while the FMA pipes ran half-idle. Fix: keep the active set L1-resident for both SMT siblings (`SYNTH_L1_ELEMS`, default 1024 doubles), issue 2 passes of memory-FMAs to saturate both load AGUs and both FMA pipes, write back only sparsely (`SYNTH_STORE_COUNT`), and let the integer MixGpr chains co-saturate the integer cluster in parallel. Knobs were `-D`-overridable; `sweep_power.ps1` found the per-CPU optimum. Distinct from the failed 2026-05-14 pure reg-reg (kept idle load units) and 2026-05-23 bigger-buffer (DRAM stalls) directions.

**2026-06-06 — Prior power retune (superseded)**: The 2026-06-04 div/sqrt-heavy experiment was superseded for synthetic scalar, AVX2, and AVX-512. That direction favored sustained execution-unit activity: smaller active synthetic buffers, FMA or split mul/add, shuffle/permute pressure, and high-entropy integer multiply/rotate/xor chains.

## 2026-06-13 Upstream-Style Power Redesign Detail

### Why the change
Direct comparison against the upstream GitHub release showed higher sustained CPU package power on a Ryzen 7 5700X with raised PBO limits. The local L1-resident/sparse-store design maximized FMA throughput but left memory-subsystem and integer-division power on the table.

### Current workload contract
- **Realistic scalar**: `RunRealisticCompilerSim_V3` is intentionally kept close to upstream; the hot string-table lookup no longer has a defensive bounds check (saves a branch per candidate).
- **Synthetic scalar/SSE2/NEON**: fixed 65536 doubles/thread buffer (512 KiB, L2/L3 traffic). 16 XMM/NEON registers, store-every-result (`_mm_storeu_pd` / `vst1q_f64`), 64-bit GPR integer division interleaved with the vector WORK. x86 SSE2 uses split `_mm_mul_pd` + `_mm_add_pd` (not FMA) for double µop count. No vector div/sqrt.
- **AVX2**: 16 YMM registers, one pass of 16 store-every-result FMAs per iteration, **16 GPR multiply-xor chains** (was 8), 4 `_mm256_permute4x64_pd` per iteration for port-5 shuffle pressure. 512 KiB buffer.
- **AVX-512**: 32 ZMM registers, one pass of 32 store-every-result FMAs per iteration, **16 GPR multiply-xor chains** (was 8), 4 `_mm512_permutex_pd` per iteration, `_mm512_cmp_pd_mask` + `_mm512_mask_blend_pd` for mask register pressure. 512 KiB buffer.
- **Decompression**: keeps the local 256 KiB buffer, 256 passes, and **3 × 64-bit IDIV every 64 bytes** (was 1).
- **RAM**: 70 % of available physical RAM capped at 16 GiB. 5-second bursts alternate between a **4-accumulator integer multiply chain** write-stride pass (was `p[i] = p[i] + 1`) and a pointer-chase loop.
- **I/O**: single thread, direct/unbuffered 256 KiB random reads from a 512 MiB temp file, **full-buffer multiply-XOR hash** over the read buffer (was minimal `p[0] ^ p[read-1]` sink).
- **`--perf-stats`**: initializes `g_Cpu = GetCpuInfo()` and calls `SetFpuFlushMode()` before timing.

### RAM/I/O subsystem notes
- **RAM**: 70 % of available physical RAM, capped at 16 GiB. 5-second bursts alternate between a 4-accumulator integer multiply chain write-stride pass (read 4 → multiply-XOR → write 4 per iteration) and a pointer-chase loop. Allocation is reused across bursts.
- **I/O**: single thread, direct/unbuffered 256 KiB random reads from a 512 MiB temp file, full-buffer multiply-XOR hash over the read buffer to keep the IO core's integer units active. Temp files use predictable names and no symlink/TOCTOU hardening.

### Build flags
- **LLVM MinGW path**: `-O3 -ffast-math -funroll-loops -fno-strict-aliasing -fno-rtti -fno-exceptions -fno-stack-protector -fomit-frame-pointer -flto -s`. Both flags restored as they benefit synthetic workload power draw. `-nounroll` build variants (`bin/x64-llvm-v3-nounroll`) omit `-funroll-loops` and `-fno-strict-aliasing` for comparison.
- **Zig path (including Windows)**: same flags as LLVM MinGW. `-nounroll` variants available (`bin/x64-zig-v3-nounroll`).
- Both paths keep `-ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident`.
- Synthetic-kernel target attributes include `hot` to prioritize their icache footprint.

### Tests updated
- Source-invariant tests assert the expanded workload profile (buffer hash, RAM 4-accumulator, IO hash, 16 GPRs in AVX2/AVX-512).
- `RunRealisticCompilerSim_V3` source-hash baseline unchanged.
- `python tests/run_tests.py --stress --bin bin/x64-llvm-v3/ShaderStress.com`: 44/44 passed.
- `python tests/run_tests.py --sanitize`: 39/39 passed.

### Build fixes
- macOS: renamed RAM-stress loop variable to avoid shadowing the Mach `host_statistics64` `count` parameter.
- macOS: made `-fno-semantic-interposition` Linux-only to silence unused-argument warnings.

## 2026-06-06 CPU Power Retune Plus Subsystem Audit (superseded)

### Workload contract (historical)
- **Realistic scalar**: `RunRealisticCompilerSim_V3` intentionally unchanged; tests pin its source hash.
- **Synthetic scalar**: active work set was `SYNTH_WORK_BUF_ELEMS = 8192` doubles (64 KiB per thread). x86 SSE2 split mul/add used `Sse2SplitMulAddNoContract()` with a local inline-asm barrier so Clang fast-math could not contract it back to FMA. Hot-loop vector div/sqrt and GPR division were removed; integer pressure came from `MixGpr()` multiply/rotate/xor chains plus modest SSE/NEON shuffle work.
- **AVX2**: active work set was 64 KiB, kept 16 YMM accumulators, removed `_mm256_div_pd`/`_mm256_sqrt_pd`, and used 16 memory FMA calls plus a small in-register FMA+`_mm256_permute4x64_pd` slice.
- **AVX-512**: kept 32 ZMM accumulators and the 256 KiB allocation, removed `_mm512_div_pd`/`_mm512_sqrt_pd`, and used memory FMA plus a small in-register FMA+`_mm512_shuffle_pd` slice.

### RAM/I/O subsystem notes (historical)
- **RAM**: capped at 1.5 GiB; streaming used the full allocated byte count. Pointer chasing got a separate `chaseCount`/mask via `RoundDownPowerOfTwo(streamCount)` and initialization through `InitializeRamChase()`.
- **I/O**: Windows and Unix direct/no-buffered read paths shared `HashIoBufferForCpuPower()` with four independent vector accumulators. I/O thread policy was `min(cpu/4, 8)`.

### Follow-up / validation (historical)
- Manual admin power comparison on Ryzen 5700X was the final validation step.

## Implemented Optimizations

Note: this section preserves older audit history. When it conflicts with the 2026-06-06 section above, treat the 2026-06-06 section as current.

### Build System (build.py)

- **Windows**: LLVM MinGW 20260519 (LLVM 22.1.6) via mstorsjo/llvm-mingw — `clang++` / `lld` replaces `zig c++` for all Windows targets.
- **Linux/macOS**: Zig 0.15.2 cross-compiler still used for non-Windows targets.
- **x86_64_v4 targets**: `bin/x64-llvm-v4` and `bin/linux-x64-v4` build configs enabling AVX-512F/BW/CD/DQ/VL for compiler auto-vectorization of non-hot code paths. Native builds auto-select highest variant (v4 > v3 > baseline).
- **Output directories renamed**: `bin/x64-zig*` → `bin/x64-llvm*`, `bin/arm64-zig` → `bin/arm64-llvm`.
- **`-fno-stack-protector`**: Removes stack canary checks from every function (acceptable for stress tool).
- **`-fomit-frame-pointer`**: Frees RBP as GP register on x86-64.
- **`-fno-exceptions`**: Disables C++ exception handling entirely (no try/catch/throwing code in codebase). Removes personality functions, landing pads, and exception tables — improves icache density. Zero risk.
- **`-fno-semantic-interposition`**: Prevents symbol interposition, allowing more aggressive inlining (complementary to LTO).
- **Linux linker flags**: `-Wl,--sort-common,--sort-section=alignment` for better cache locality; `-Wl,--gc-sections` to remove unreferenced sections (requires `-ffunction-sections`/`-fdata-sections`).
- **`-mprefer-vector-width=512`**: Forces 512-bit ZMM register usage on x86_64_v4 targets for all auto-vectorized loops (init, golden verify).
- **REMOVED 2026-05-23**: `-frename-registers`, `-fweb`, `-funroll-all-loops`, `-fpeel-loops`, `-fcf-protection=full`. These flags made the code too efficient (fewer cycles/iteration), reducing sustained power draw. The online release uses vanilla `-O3` without these. For a stress test, less efficient code draws more power.
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
- **AVX-512 mask register pressure**: Added `_mm512_cmp_pd_mask` + `_mm512_mask_blend_pd` in `RunHyperStress_AVX512` hot loop. Keeps mask register file (k0–k7) active alongside vector pipes, utilizing compare and blend hardware. (Re-added 2026-05-14, reverted 2026-05-23 when mask ops were removed to match proven online design.)
- **Cross-lane reduction at function exit**: Added shuffle+add merge step at the end of all 4 workload reduction phases (SSE2, NEON, AVX2, AVX-512). Adds extra shuffle-port pressure during the hot reduction sequence.
- **Thread affinity re-assertion**: WorkerThread now re-pins to the assigned core every 10 seconds, preventing OS migration during idle phases in dynamic mode.

- **SSE2 FMA**: `SSE2_WORK` macro conditionally uses `_mm_fmadd_pd` when compiled with `__FMA__` defined (v3/v4 builds). Falls back to separate `_mm_mul_pd` + `_mm_add_pd` for generic x86_64.
- **Prefetch distance doubled**: All 4 workload paths (SSE2, NEON, AVX2, AVX-512) now prefetch 2 strides ahead instead of 1, for better cache coverage.
- **Noexcept parsers**: Replaced `std::stoull`/`std::stoll`/`std::stoi` with `std::from_chars` in `ParseUint64`, `ParsePositiveInt`, `AskWizardChoice`. Eliminates exception handling code/data from all 3 functions.
- **`[[unlikely]]` annotations**: C++20 `[[unlikely]]` added to `g_App.quit` break checks in all 4 workload hot loops (RealisticCompilerSim, SSE2/NEON, AVX2, AVX-512), plus `w.terminate` loop in `WorkerThread`, `g_Repro.active` check, and IO thread idle/init paths. Compiler optimizes branch layout for the hot path.
- **RAM stress stride tuning**: Reduced write pattern stride from 64 elements (512 bytes / 8 cache lines) to 1 element (8 bytes), increasing memory controller write transactions. Changed ratio from 50/50 to 70/30 (70% high-bandwidth stride writes, 30% pointer-chase latency stress). Applied to both Windows and Linux paths.
- **Linux `mlock()`**: `ScopedMem` now calls `mlock()` after `mmap` on Linux to prevent page swapping during RAM stress. Best-effort; silently ignored without `CAP_IPC_LOCK`.
- **Multi-thread IO stress**: Increased from single IO thread to up to `min(cpu/4, 8)` IO threads with separate temporary files, improving disk controller queue depth and IO subsystem utilization.
- **AVX2 workload: 8-WORK proven design (2026-05-23 revert)**: Reverted from pure reg-reg + L1 traffic back to 8 memory WORK calls with FMA + 8 GPR multiply‑XOR chains (matching online release). Removed all permutes/suffles and reg‑reg FMAs (keeps loop compact for µop cache). 512KB buffer.
- **SSE2/Scalar 48‑WORK proven design (2026-05-23 revert)**: Reverted from pure reg‑reg back to the proven 48‑WORK mixed memory+compute design (matching the online GitHub release which empirically draws more power). Uses split `_mm_mul_pd + _mm_add_pd` (not FMA) for double µop count. Integer division on 16 GPRs creates sustained pipeline backpressure. Buffer increased from 256KB→512KB to cause L2 misses → memory controller activity. No shuffles or reg‑reg FMAs (avoids µop cache bloat). Iteration count: `complexity * 280`. Same applied to NEON.
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

## 2026-06-04 Inversion: cache residency + expensive compute ops (superseded)

Superseded by the 2026-06-13 upstream-style redesign. Historical note: this inverted the 2026-05-23 "L2-miss → memory controller activity" design. Per user note at the time: data staying in CPU caches was thought to yield higher package power than data spilling to DRAM. The 2026-06-13 redesign shows that, for this use case, the upstream L2/L3-resident + store-every-result profile draws more power on a Ryzen 5700X.

### Reverted 2026-05-23 changes
- **`WORK_BUF_ELEMS` 65536 → 32768** (512 KB → 256 KB, L2-resident on all modern CPUs). MASK values re-derived.
- **RAM stress cap**: 70 % of available memory (max 16 GB) → fixed 1.5 GB. DRAM-spilling lowers power.
- **Decompressor `PASSES` 128 → 256**: more sustained integer-pipe work, buffer still L2-resident.
- **GPR chains**: AVX-2 8 → 16, AVX-512 8 → 16 (more integer-pipe pressure).

### New expensive compute ops (replacement, not addition — no register spill)

To keep the 32-ZMM / 16-YMM / 16-XMM / 16-NEON register files intact, the new vec-div / vec-sqrt ops REPLACE some of the existing FMA / mul-add WORK calls rather than add new accumulators. The replaced ops run on the same `r` registers, so the FMA/dependent chain continues — the new ops simply feed a different execution unit.

- **AVX-512**: 4 of 32 FMA replaced with `_mm512_div_pd`; 4 replaced with `_mm512_sqrt_pd`. 24 FMA + 4 div + 4 sqrt = 32 ZMM.
- **AVX-2**: 1 of 16 FMA replaced with `_mm256_div_pd`; 1 replaced with `_mm256_sqrt_pd`. 14 FMA + 1 div + 1 sqrt = 16 YMM.
- **SSE2**: 1 of 48 split-mul-add replaced with `_mm_div_pd`; 1 with `_mm_sqrt_pd`.
- **NEON (ARM64)**: 2 of 48 NEON_WORK replaced with `vdivq_f64`; 2 with `vsqrtq_f64`.

### IO thread 2nd-pass AVX2 hash
- `IOThread` (Windows + Linux): added a 2nd hash pass over the 256 KB read buffer using `_mm256_loadu_si256` + `_mm256_mul_epu32`. Gated on `__AVX2__`. Doubles the per-IO-completion CPU burst, keeping the IO core hot.

### Decompressor 64-bit IDIV
- Added `acc = acc / ((data[i] & 0xFFFFFFFFULL) | 1ULL)` every 64 bytes inside the `RunDecompressLogic` inner loop. ~20-40 cycle port-0 latency per call. PASSES doubled, so ~1M IDIV per call. Buffer still 256 KB / L2-resident.

### Function attributes
- Added `__attribute__((hot))` to `TARGET_AVX2` and `TARGET_AVX512` (alongside the existing `noinline` and target attribute). Tells the compiler to prioritize these functions in the icache. No µop-cache bloat risk.

### Rejected (not added)
- `-funroll-loops` / `-funroll-all-loops` / `-fpeel-loops`: still removed (the 2026-05-23 reasoning stands: efficient code draws less power).
- More mask-register pressure / permutes on AVX-512: still rejected (reverted 2026-05-23).
- `__attribute__((flatten))`: rejected (icache bloat risk).
- NUMA-aware allocation / huge pages: deferred; not a power-draw lever.
- Larger `WORK_BUF_ELEMS` (e.g., 768 KB): would push data further from L2; contradicts user note.

### Trade-off
On Intel Skylake-X+ (and Emerald Rapids), the AVX-512 path may trigger AVX-512 frequency throttling because all 32 ZMM + 8 div + 4 sqrt per iter keep the core very busy. This is a feature, not a bug — throttling is a sign the core is at the power/thermal limit. If measured frequency drops too far, reduce the div/sqrt count from 4+4 to 2+2.
