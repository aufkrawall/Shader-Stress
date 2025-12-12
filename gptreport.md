ShaderStress 3.1 — Full Source Review (Findings)

This review covers the provided files:
- Common.h / Common.cpp
- CpuFeatures.cpp
- Gui.cpp
- Platform.cpp
- ShaderStress.cpp (Win GUI + Linux/macOS CLI)
- Threading.cpp
- Workloads.cpp

Focus: randomness/distribution of “pseudo-shaders”, stability-testing quality (per-thread load variation), and other bugs/redundancies/performance/design issues—especially risks of extra threads on Linux/macOS affecting benchmark performance.

--------------------------------------------------------------------
1) Randomness & “optimal” per-thread load variation
--------------------------------------------------------------------

1.1 It is not “perfectly random”
Several components are deterministic or periodic:

A) Complexity generation is periodic per thread
- RunCompilerLogic() uses thread_local pregenComplexity[1024], initialized once with mt19937 seeded by (1234 + idx), then cycles forever (complexityIdx++ & 1023).
- Result: each worker repeats the same 1024-complexity pattern for the lifetime of the thread.

B) Seed generation is weakly varying
seed = GetTick() ^ (idx<<32) ^ (localShaders * GOLDEN_RATIO);
- GetTick() is millisecond-resolution; multiple threads often share the same tick.
- idx<<32 is constant per worker; localShaders increments linearly.
- This provides variation but is not high-quality randomness and can correlate across threads.

C) Decompress logic uses deterministic RNG
- mt19937 rng(idx * 777), one-time init, then deterministic mutation.

D) Kernels are deterministic transforms
- AVX2/AVX512/scalar and “realistic” sim are deterministic math/bit patterns driven by the seed.

Conclusion: the workload is pseudo-random and repeatable, not perfectly random.

1.2 Is it optimal for stability testing with constantly changing per-thread load?
Not strictly “optimal” if the goal is maximally de-correlated changing load on every CPU thread.

What you already do well
- Exponential complexity distribution creates bursts that can generate power/thermal/current transients (good for some stability goals).
- Realistic compiler sim mixes hashing, pointer chasing, ALU pressure, and bitvector ops (good coverage).
- Repeatability helps debugging and repro.

Where it falls short
- 1024-cycle periodic complexity patterns can re-align across threads, especially after synchronized start, leading to correlated bursts.
- Tick-based seeding can correlate jobs across threads.
- Steady mode forces constant complexity (12000), reducing variation.

If you want better per-thread de-correlation
- Use per-thread PRNG state advanced per job (splitmix64/xoshiro) instead of cycling a fixed table.
- Randomize not just complexity but also bounded knobs per job (fma_intensity, int_intensity, mem_pressure, branch_freq), or periodically shuffle configs.
- Keep deterministic repro mode as a separate explicit path.

--------------------------------------------------------------------
2) Linux/macOS: risk of spawning unnecessary workers that reduce benchmark performance
--------------------------------------------------------------------

2.1 Current architecture mostly avoids extra stress threads during benchmark
Linux/macOS benchmark path:
- g_Workers is created with cpu = hardware_concurrency().
- SetWork(cpu, 0, false, false) is used.
- SetWork reserves threads for IO/RAM only when requested; benchmark passes both false.
- IO/RAM threads are spawned lazily only when toggled.

This largely prevents the historical regression where benchmark accidentally included IO/RAM or extra stress threads.

2.2 Remaining regression vectors
You can still regress benchmark performance if:
- A future change calls SetWork(..., io=true, ram=true) while g_App.mode==0.
- SetWork is invoked before g_Workers is sized (budget miscomputed).
- DynamicLoop thread is accidentally running in benchmark mode.

Hardening suggestion
- Add a guard inside SetWork:
  - if g_App.mode == 0 then force io=false and ram=false
  - optionally disallow decompressor threads too if benchmark definition is compute-only
This directly addresses your past issue: even if someone changes GUI/CLI logic later, SetWork enforces benchmark cleanliness.

--------------------------------------------------------------------
3) Bugs / correctness issues
--------------------------------------------------------------------

3.1 Benchmark workload enforcement mismatch (GUI vs actual execution)
GUI benchmark mode forces:
- g_App.selectedWorkload = WL_SCALAR_SIM

But:
- ISA buttons remain clickable in benchmark mode.
- UnsafeRunWorkload() respects g_App.selectedWorkload and can run AVX2/AVX512 etc.
- The benchmark report in Watchdog() hardcodes: “Workload: Scalar real.”

Impact
- You can produce benchmarks that are not actually “Scalar realistic” while reporting they are.
- Hash does not encode workload selection, so results become ambiguous/misleading.

Fix options
1) Disable ISA selection in benchmark mode (UI + input handling).
2) Force WL_SCALAR_SIM in the dispatcher when g_App.mode==0 regardless of selectedWorkload.
3) At minimum, report the actual resolved ISA used at completion and include it in the hash if you want verifiable comparability.

3.2 Potential undefined behavior on GCC/Clang: clz/ctz of zero
In Common.h non-MSVC mappings:
- _lzcnt_u64 -> __builtin_clzll
- _tzcnt_u64 -> __builtin_ctzll
But __builtin_clzll(0) and __builtin_ctzll(0) are undefined behavior.

RunRealisticCompilerSim_V3 can execute these on vr[src1] which can become zero.

Fix
- Implement safe wrappers:
  - if x==0 return 64 (matching lzcnt/tzcnt semantics on x86)
This is a correctness and portability fix for Linux/macOS.

3.3 MSVC compatibility: __attribute__((target("xsave")))
CpuFeatures.cpp defines safe_xgetbv with __attribute__((target("xsave"))).
MSVC does not accept __attribute__ (unless using clang-cl). If you build with MSVC, this can break.

Fix
- Guard attributes under __clang__/__GNUC__ or provide MSVC alternative.

3.4 Hash scheme: misleading comment + weak validation
The comment claims an 8-bit checksum and 68-bit layout, but implementation uses only a 4-bit checksum nibble (check & 0xF).
Validation is therefore weak: random corruption has 1/16 chance to pass.

Also, cpuHash is decoded but never compared to local CPU, so “VALID” means “checksum nibble matches,” not “this came from a legitimate run on this CPU.”

Fix options
- Increase checksum size (e.g., 16 bits) or use a stronger integrity approach.
- Change UI wording to “Structurally valid” vs “Matches this CPU.”
- If you want the hash to validate origin, verify cpuHash against current CPU (or include more context).

3.5 macOS RAM availability is a placeholder
macOS RAM thread uses a hardcoded fallback availPhys = 8GB, then allocates ~70% of that.
This can cause severe memory pressure or swapping on machines with less free memory.

Fix
- Use real available memory estimation (vm_statistics64 / host_statistics64), or default to a conservative cap unless user opts in.

--------------------------------------------------------------------
4) Performance and design issues
--------------------------------------------------------------------

4.1 Realistic compiler sim allocates large buffers every job (allocator noise)
RunRealisticCompilerSim_V3 allocates multiple large arrays every call:
- tree nodes, table entries, string pool, bitvectors
This adds allocator overhead and variability, and can distort “jobs/s” toward allocator/memory behavior rather than CPU execution.

Fix
- Make these buffers thread_local and reuse them; re-seed contents per job without reallocating.

4.2 SetWork thread create/join churn in Dynamic mode
DynamicLoop calls SetWork frequently; SetWork can terminate/join threads and respawn them.
Thread create/join is expensive and can add jitter and distort stress behavior.

Fix
- Keep a fixed-size worker pool and switch roles (compiler/decomp/idle) via atomics. Only IO/RAM threads need to be optional.

4.3 Linux pinning may be invalid under cpusets/containers
PinThreadToCore(idx) on Linux uses CPU_SET(coreIdx) directly and ignores errors.
Under cpuset constraints this can fail or lead to suboptimal scheduling.

Fix
- Check pthread_setaffinity_np return code.
- Map idx to allowed CPUs using sched_getaffinity.

4.4 Windows GUI backbuffer resources leak on exit (minor)
WM_PAINT uses static s_memDC/s_memBM, deleted on resize but not on destroy. OS will reclaim at process exit, but it’s still a leak.

Fix
- Free them in WM_DESTROY or WM_NCDESTROY.

--------------------------------------------------------------------
5) Redundancies / cleanup
--------------------------------------------------------------------

- Linux/macOS ShaderStress.cpp includes iostream and signal.h twice (harmless but sloppy).
- Base62 decode scans alphabet linearly per character (tiny cost; can be replaced with a lookup table).
- cpuHash is included in hash but not verified; either verify or present as informational.

--------------------------------------------------------------------
6) Direct answers
--------------------------------------------------------------------

Is the math/distribution perfectly random for optimal stability testing (optimally changing load on every cpu thread)?
No.
- Complexity is periodic per thread (1024-cycle).
- Seeds can correlate (ms tick).
- Many parts are deterministic by design.

It is still a valid stress workload, but not “perfectly random” nor maximally de-correlated.

Other bugs/redundancies/performance/design flaws?
Highest-impact issues:
1) Potential UB on Linux/macOS from clz/ctz(0) mappings.
2) Benchmark enforcement/reporting mismatch (GUI allows ISA changes; report hardcodes scalar realistic).
3) MSVC build fragility due to __attribute__((target)) usage.
4) Hash validation is weak (4-bit checksum) and “VALID” wording is misleading.
5) Realistic sim per-job allocations add overhead/noise and can distort benchmark/stress signal.
6) Dynamic mode thread churn (create/join) is costly; fixed pool is preferable.
7) macOS RAM availability is a placeholder and can over-allocate.

--------------------------------------------------------------------
7) Targeted hardening to prevent future Linux/macOS benchmark regressions (your note)
--------------------------------------------------------------------

To ensure benchmark mode never spawns unnecessary stress workers again, even if someone changes UI/CLI logic later:

1) Enforce benchmark constraints inside SetWork():
- if g_App.mode == 0:
  - io = false
  - ram = false
  - optionally requestDecomp = 0

2) Enforce benchmark workload inside the dispatcher or UI:
- If benchmark is meant to be fixed, force WL_SCALAR_SIM in UnsafeRunWorkload when mode==0 and disable ISA selection in GUI/CLI interactive benchmark.

3) Stabilize the realistic workload by removing allocator noise:
- Make realistic sim structures reusable (thread_local) so benchmark measures CPU work more consistently and doesn’t fluctuate with allocator behavior.