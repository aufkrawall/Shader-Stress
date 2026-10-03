# Recent Changes Log

## 2026-10-03 — v3.6.0: verified, bounded kernels; paired job verification; scheduler/testers rewrite

Root causes found (all confirmed, see `llm-wiki/opt-audit.md` and `verification.md`):
- Synthetic SSE2/AVX2/AVX-512 kernels overflowed to `inf` after ~0.05-0.16% of each job
  (feedback `r = r*1.000001 + stored r`); scalar IDIV chains collapsed to 0
  (`--perf-stats` result `0x7ff0000000000000`). AVX2 was latency-bound on its GPR chain
  (~0.31 FMA ops/cycle). All 2026-05/06 power comparisons were therefore confounded.
- Only golden checks (~1% of work) were verified; decompression/RAM/IO never.
- `build.py --sanitize` never applied the sanitizer (`SANITIZER_MODE` not `global`), so
  sanitizer "tests" ran release binaries. Real UB then found: `Rotl64` counts >= 64 and
  `>> 64` in the realistic sim rotate (fixed; golden checksum unchanged).
- Dynamic mode re-created the 512 MiB IO file / 16 GiB RAM allocation on every toggle and
  blocked `SetWork` while joining; idle workers polled `sleep_for(1ms)`; jobs were not
  preemptible; phases 7/8 always used CPU 0/1; phase 13 was a constant 2-thread loop.
- `--threads 2` steady mode had 0 compute workers (RAM+IO reservation).

Changes: new unitary butterfly kernels (`SynthKernel.inc`), paired verification
(`Verification.cpp`, `Worker.cpp`), topology-aware pinning (`Topology.cpp`), event-driven
scheduler with preemption + core-cycle mode (`Scheduler.cpp`), verified RAM/IO testers,
LZ decompression workload, crash reports + PDB/debug symbols, strict IEEE FP, CLI split
and new options, `--self-test`, rewritten `tests/run_tests.py`, llm-prompt-templates
default integration (secret-leak gate, changelog, debug-tools pages, discovery script).

Verification: 13/13 release targets build; `python tests/run_tests.py --stress --sanitize`
all green (UBSan + ASan run the self-test). Single-thread `--perf-stats` (5700X): AVX2
~1.67 FMA-pipe ops/core-cycle (83% of peak) vs 0.31 before.

Open: package power not measured (needs elevated `sweep_power.ps1`); AVX-512 kernel
untested on hardware; Linux/macOS binaries not executed.

## 2026-06-17 — CPU power draw improvements: IO/RAM/decomp compute, AVX2/AVX-512 16 GPRs, permutes, mask ops

Goal: increase CPU package power for synthetic workloads (scalar, AVX2, AVX-512, NEON, RAM, IO, decompression) by adding execution-unit pressure beyond the upstream-style 2026-06-13 profile.

Changes:
- **Threading.cpp — IO thread**: Replaced minimal `volatile uint8_t sink = p[0] ^ p[read - 1]` with a full-buffer FNV-1a-like multiply-XOR hash over the 256 KiB read buffer. Keeps the IO core's integer execution units active alongside storage operations. Applied to both Windows and Linux paths.
- **Threading.cpp — RAM thread**: Replaced `p[i] = (p[i] + 1)` write-stride pass with a 4-accumulator integer multiply chain (read 4→hash→write 4), using four independent `a0..a3` registers and the golden-ratio constant. Keeps the RAM core's integer cluster hot during memory stress. Applied to both Windows and Linux paths.
- **Threading.cpp — Decompression**: Added 2 more 64-bit IDIV operations at offsets 16 and 32 within each 64-byte window (was 1 IDIV at offset 0, now 3 total). Triples high-latency port-0 backpressure.
- **Workloads.cpp — AVX2**: GPR chains expanded from 8 to 16 (g0–g15). 4 `_mm256_permute4x64_pd` operations added per iteration for port-5 shuffle pressure.
- **Workloads.cpp — AVX-512**: GPR chains expanded from 8 to 16 (g0–g15). 4 `_mm512_permutex_pd` operations added per iteration for port-5 shuffle pressure. `_mm512_cmp_pd_mask` + `_mm512_mask_blend_pd` added for mask register file pressure.
- **build.py**: Restored `-funroll-loops` and `-fno-strict-aliasing` to the LLVM MinGW path. Added `-nounroll` build variants (`win-v3-nounroll`, `zig-v3-nounroll`) that omit these flags for comparison. Zig path also gates these flags behind the nounroll suffix.
- **tests/run_tests.py**: Updated IO invariant test to check for the new buffer hash pattern. Renamed test function accordingly. All 44 non-stress + 5 stress + 2 golden + 2 UBSan tests pass.

Verification:
- `python build.py win-v3 win-v3-nounroll zig-v3 zig-v3-nounroll`: 4/4 targets succeeded.
- `python tests/run_tests.py --stress --bin bin/x64-llvm-v3/ShaderStress.com`: 44/44 passed.
- `python tests/run_tests.py --sanitize`: 39/39 passed (no stress).

## 2026-06-13 — Power gap follow-up: compiler flags, Zig Windows, security hardening removal

Problem: after the upstream-style redesign, synthetic scalar/AVX2 power increased,
but all variants still lagged the GitHub release binary, and scalar-sim (realistic)
power dropped from ~116 W to ~111 W.

Root causes found:
- `-funroll-loops` and `-fno-strict-aliasing` (copied from the upstream Zig build)
  reduced realistic-workload power when used with the LLVM MinGW toolchain.
- The GitHub release binary is built with Zig, not LLVM MinGW; local builds lacked
  a Zig Windows target for an apples-to-apples comparison.
- Local hardening added to `RunRealisticCompilerSim_V3` (string-table bounds check)
  and `IOThread` (symlink/TOCTOU defenses, random filenames, canonical-path checks)
  sacrificed power for security the user does not need in a stress tester.
- `WorkerThread` re-pinned itself every 10 s; upstream does not.
- `TARGET_AVX2` / `TARGET_AVX512` macros lost the `hot` attribute in the redesign.

Changes:
- `build.py`: removed `-funroll-loops` and `-fno-strict-aliasing` from the LLVM MinGW
  path; kept them on the Zig path to match the upstream release. Restored `hot`
  attribute to synthetic-kernel target macros. Added Zig Windows build configs
  (`bin/x64-zig`, `bin/x64-zig-v3`, `bin/arm64-zig`) and `zig` / `zig-v3` aliases.
- `Workloads.cpp`: removed the defensive string-table bounds check from the hot loop
  in `RunRealisticCompilerSim_V3`.
- `Threading.cpp`: simplified `IOThread` to match upstream (predictable temp filename,
  `CREATE_ALWAYS`, no `O_NOFOLLOW`/canonical-path checks, deterministic fill).
  Removed the 10 s re-pinning loop from `WorkerThread`.
- `tests/run_tests.py`: updated `RunRealisticCompilerSim_V3` source-hash baseline.

Verification:
- `python build.py`: 13/13 targets succeeded (LLVM MinGW + Zig Windows, Linux, macOS).
- `python tests/run_tests.py --stress --sanitize --bin bin/x64-llvm-v3/ShaderStress.com`: 46/46 passed.
- `python tests/run_tests.py --stress --bin bin/x64-zig-v3/ShaderStress.com`: 44/44 passed.

## 2026-06-13 — Upstream-style power redesign

Goal: match/beat the upstream GitHub release's sustained CPU package power on a
PBO-unlocked Ryzen 7 5700X.

Root cause of the local power gap:
- Local synthetic kernels used a tiny L1-resident buffer and sparse stores to
  maximize FMA throughput; upstream uses a 512 KiB/thread buffer, store-every-result,
  and GPR integer division, which keeps the memory subsystem and integer division
  units busy alongside FP.
- Local RAM stress was capped at 1.5 GiB; upstream allocates 70 % of available RAM
  (max 16 GiB), drawing more IMC/DRAM power.
- Local IO stress used up to 8 threads with AVX2 hashing, stealing cores from the
  heavy synthetic kernels; upstream uses a single minimal IO thread.

Changes:
- `build.py`: added `-funroll-loops` and `-fno-strict-aliasing` to release builds.
- `Workloads.cpp`: reverted synthetic scalar/SSE2/NEON, AVX2, and AVX-512 kernels
  to the upstream profile (65536 doubles/thread, store-every-result, GPR IDIV in
  scalar/SSE2/NEON, 8 GPR chains for AVX2/AVX-512).
- `Common.h`: removed `RAM_STRESS_MAX_BYTES`.
- `Threading.cpp`: RAM stress now allocates 70 % of available RAM / 16 GiB cap with
  write-stride + pointer-chase bursts. IO stress reverted to single thread with
  minimal `p[0] ^ p[read-1]` sink. Removed `HashIoBufferForCpuPower`,
  `RunRamStreamingPass`, `InitializeRamChase`, and `RoundDownPowerOfTwo`.
- `tests/run_tests.py`: updated source-invariant tests to assert the upstream-style
  profile.
- `llm-wiki/opt-audit.md` and `llm-wiki/index.md`: documented the redesign.

Verification:
- `python build.py`: 10/10 targets succeeded (Windows/Linux/macOS x64 + ARM64).
- `python tests/run_tests.py --stress --sanitize`: 46/46 passed.
- Decompression (`RunDecompressLogic`) kept its local IDIV-heavy 256-pass design.

Fixes during integration:
- macOS build: renamed RAM-stress loop variable to avoid shadowing the Mach
  `host_statistics64` `count` parameter.
- macOS build: made `-fno-semantic-interposition` Linux-only (it is unused on
  macOS and produced warnings).
- `tests/run_tests.py`: relaxed `test_invariant_ram_upstream_pattern` regexes
  to accept the Linux/macOS `ramCount` variable name.

Older entries: [archive/2026-05-to-06.md](archive/2026-05-to-06.md).
