# Recent Changes Log

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
