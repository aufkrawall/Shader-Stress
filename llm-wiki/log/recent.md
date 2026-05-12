# Recent Changes Log

## 2026-05-12 — Optimization Audit

- **Build**: Added x86_64_v4 targets (AVX-512 baseline) for Windows and Linux
- **Build**: Added `-frename-registers`, `-fweb`, `-fno-stack-protector`, `-fomit-frame-pointer`, Linux linker sort flags
- **Build**: Native target now prefers highest CPU variant (v4 > v3 > baseline)
- **Platform**: Linux power management — sets scaling governor to 'performance' via sysfs
- **Platform**: Hybrid CPU topology detection in CpuFeatures (isHybrid flag)
- **Code**: SSE2 scalar path uses `_mm_fmadd_pd` when `__FMA__` is defined (v3/v4 builds)
- **Code**: Prefetch distance doubled (2 strides ahead) for all workload paths
- **Code**: Replaced all `std::stoull`/`std::stoll`/`std::stoi` with noexcept `std::from_chars`
- **Skipped**: Windows power scheme (too invasive), hybrid P-core pinning (complex),
  PGO (complex build), macOS LTO (needs investigation)
- **llm-wiki**: Created initial wiki pages (index, overview, opt-audit, log)
