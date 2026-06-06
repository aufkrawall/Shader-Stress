#!/usr/bin/env python3
"""
ShaderStress test runner.

Default: runs only lightweight CLI-level tests (no CPU stress).
Use --stress to include workload / repro / benchmark tests.

Usage:
    python tests/run_tests.py                         # CLI-only tests
    python tests/run_tests.py --stress                 # Also run CPU-stressing workload tests
    python tests/run_tests.py --stress --record-golden # Record golden-value baseline
    python tests/run_tests.py --bin <path>             # Use specific binary
"""

import subprocess
import sys
import os
import json
import glob
import hashlib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN_FILE = os.path.join(os.path.dirname(__file__), "golden_values.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_binary():
    candidates = [
        os.path.join(PROJECT_ROOT, "bin", "x64-llvm", "ShaderStress.com"),
        os.path.join(PROJECT_ROOT, "bin", "x64-llvm-v3", "ShaderStress.com"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    matches = glob.glob(os.path.join(PROJECT_ROOT, "bin", "**", "ShaderStress.com"), recursive=True)
    if matches:
        return matches[0]
    for root, dirs, files in os.walk(os.path.join(PROJECT_ROOT, "bin")):
        for f in files:
            if f == "shaderstress":
                return os.path.join(root, f)
    return None


def run(binary, args, timeout=30):
    cmd = [binary] + args
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=PROJECT_ROOT)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", b"TIMEOUT"
    except FileNotFoundError:
        return -2, b"", b"FILE NOT FOUND"


PASS = 0
FAIL = 0

def check(ok, msg):
    global PASS, FAIL
    if ok:
        print(f"  [OK] {msg}")
        PASS += 1
    else:
        print(f"  [FAIL] {msg}")
        FAIL += 1


# ---------------------------------------------------------------------------
# Lightweight CLI tests (no CPU stress)
# ---------------------------------------------------------------------------

def test_help(binary):
    ret, out, err = run(binary, ["--help"])
    text = out.decode(errors="replace")
    check(ret == 0 and "Usage:" in text and "--mode" in text, "--help")


def test_version(binary):
    ret, out, err = run(binary, ["--version"])
    text = out.decode(errors="replace")
    check(ret == 0 and "ShaderStress" in text, "--version")


def test_verify_invalid(binary):
    ret, out, err = run(binary, ["--verify", "SS3-0000000000000000"])
    text = out.decode(errors="replace")
    check(ret == 4 and "INVALID" in text, "--verify (invalid hash)")


def test_verify_malformed(binary):
    ret, out, err = run(binary, ["--verify", "not-a-hash"])
    check(ret == 4, "--verify (malformed)")


def test_verify_empty(binary):
    ret, out, err = run(binary, ["--verify", ""])
    check(ret == 4, "--verify (empty)")


def test_verify_bad_prefix(binary):
    ret, out, err = run(binary, ["--verify", "XX3-0000000000000000"])
    check(ret == 4, "--verify (bad prefix)")


def test_invalid_arg(binary):
    ret, out, err = run(binary, ["--nonexistent"])
    text = err.decode(errors="replace")
    check(ret == 2 and "Error" in text, "invalid argument")


def test_missing_mode_value(binary):
    ret, out, err = run(binary, ["--mode"])
    check(ret == 2, "--mode (missing value)")


def test_invalid_mode_value(binary):
    ret, out, err = run(binary, ["--mode", "invalid", "--duration", "1"])
    check(ret == 2, "--mode (invalid value)")


def test_missing_isa_value(binary):
    ret, out, err = run(binary, ["--isa"])
    check(ret == 2, "--isa (missing value)")


def test_repro_with_benchmark_conflict(binary):
    ret, out, err = run(binary, ["--repro", "1", "1", "--benchmark"])
    check(ret == 2, "--repro + --benchmark conflict")


def test_verify_with_mode_conflict(binary):
    ret, out, err = run(binary, ["--verify", "SS3-0000000000000000", "--mode", "steady"])
    check(ret == 2, "--verify + --mode conflict")


def test_verify_with_wizard_conflict(binary):
    ret, out, err = run(binary, ["--verify", "SS3-0000000000000000", "--wizard"])
    check(ret == 2, "--verify + --wizard conflict")


def test_verify_with_isa_conflict(binary):
    ret, out, err = run(binary, ["--verify", "SS3-0000000000000000", "--isa", "avx2"])
    check(ret == 2, "--verify + --isa conflict")


def test_modifier_without_action(binary):
    ret, out, err = run(binary, ["--no-avx512"])
    check(ret == 2, "modifier without action")


def test_duration_zero(binary):
    ret, out, err = run(binary, ["--duration", "0"])
    check(ret == 2, "--duration 0")


def test_max_duration_alias_validation(binary):
    """--max-duration with an invalid value returns exit code 2."""
    ret, out, err = run(binary, ["--max-duration", "0"])
    check(ret == 2, "--max-duration 0")


def test_repro_missing_args(binary):
    ret, out, err = run(binary, ["--repro"])
    check(ret == 2, "--repro (missing args)")


def test_repro_partial_args(binary):
    ret, out, err = run(binary, ["--repro", "1"])
    check(ret == 2, "--repro (partial args)")


def test_repro_scalar_quick(binary):
    ret, out, err = run(binary, ["--repro", "42", "100", "--isa", "scalar", "--quiet"])
    check(ret == 0, "--repro scalar quick")


def test_repro_scalar_sim_quick(binary):
    ret, out, err = run(binary, ["--repro", "42", "100", "--isa", "scalar-sim", "--quiet"])
    check(ret == 0, "--repro scalar-sim quick")


def test_repro_high_complexity(binary):
    """Boundary test: complexity near overflow threshold (7.6M) should not crash."""
    ret, out, err = run(binary, ["--repro", "1", "8000000", "--isa", "scalar", "--quiet"], timeout=60)
    check(ret == 0, "--repro high complexity (boundary)")


def test_hash_roundtrip(binary):
    ret, out, err = run(binary, ["--hash-roundtrip"])
    text = out.decode(errors="replace")
    check(ret == 0 and "roundtrip OK" in text, "--hash-roundtrip")


# ---------------------------------------------------------------------------
# Source-invariant regression tests (read-only, no CPU stress)
# These verify the current workload-shape invariants are intact in the
# source tree. They grep .cpp / .h files for constants and patterns, and
# never run the actual stress workload (per AGENTS.md rule).
# ---------------------------------------------------------------------------

def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _extract_function(src, name):
    start = src.index(f"uint64_t {name}")
    brace = src.index("{", start)
    depth = 0
    for pos in range(brace, len(src)):
        ch = src[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[start:pos + 1]
    raise ValueError(f"function not closed: {name}")


def _stable_source_hash(text):
    normalized = "\n".join(line.rstrip() for line in text.splitlines())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def test_invariant_synth_work_buf_elems(binary):
    """Synthetic scalar/AVX2 use 64 KiB; AVX-512 retains the larger allocation."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    check("constexpr size_t WORK_BUF_ELEMS = 32768;" in src and
          "constexpr size_t SYNTH_WORK_BUF_ELEMS = 8192;" in src and
          "constexpr int MASK_SSE2   = (SYNTH_WORK_BUF_ELEMS - 2);" in src and
          "constexpr int MASK_AVX2   = (SYNTH_WORK_BUF_ELEMS - 4);" in src,
          "synthetic scalar/AVX2 active buffer == 64 KiB")


def test_invariant_ram_stress_cap(binary):
    """RAM_STRESS_MAX_BYTES must stay at the 1.5 GiB cap."""
    src = _read(os.path.join(PROJECT_ROOT, "Common.h"))
    check("RAM_STRESS_MAX_BYTES = 1536ULL * 1024 * 1024" in src,
          "RAM_STRESS_MAX_BYTES == 1.5 GiB")


def test_invariant_decomp_passes(binary):
    """DecompressLogic PASSES must be 256 after the 2026-06-04 inversion."""
    src = _read(os.path.join(PROJECT_ROOT, "Threading.cpp"))
    check("const int PASSES = 256;" in src,
          "DecompressLogic PASSES == 256")


def test_invariant_avx512_fma_permute_no_div_sqrt(binary):
    """AVX-512 uses FMA+shuffle and does not reintroduce hot-loop div/sqrt."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    check("_mm512_fmadd_pd" in src and "_mm512_shuffle_pd" in src and
          "_mm512_div_pd" not in src and "_mm512_sqrt_pd" not in src,
          "AVX-512 uses FMA+shuffle without div/sqrt")


def test_invariant_avx2_fma_permute_no_div_sqrt(binary):
    """AVX2 uses FMA+permute and does not reintroduce hot-loop div/sqrt."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    check("_mm256_fmadd_pd" in src and "_mm256_permute4x64_pd" in src and
          "_mm256_div_pd" not in src and "_mm256_sqrt_pd" not in src,
          "AVX2 uses FMA+permute without div/sqrt")


def test_invariant_sse2_no_contract_no_div_sqrt(binary):
    """Synthetic scalar SSE2 split mul/add must not compile back into FMA."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    check("Sse2SplitMulAddNoContract" in src and
          'asm volatile("" : "+x"(prod))' in src and
          "_mm_div_pd" not in src and "_mm_sqrt_pd" not in src,
          "SSE2 split mul/add no-contract barrier, no div/sqrt")


def test_invariant_ram_full_stream_separate_chase(binary):
    """RAM stream count must cover the allocation and chase must use its own power-of-two mask."""
    src = _read(os.path.join(PROJECT_ROOT, "Threading.cpp"))
    check("RoundDownPowerOfTwo(streamCount)" in src and
          "InitializeRamChase(p, chaseCount)" in src and
          "RunRamStreamingPass(p, streamCount)" in src and
          "stream ratio=90%" in src and
          "if ((rng() % 10) < 9)" in src,
          "RAM full stream count plus separate chase mask")


def test_invariant_io_multi_accumulator_hash(binary):
    """IOThread must use the shared multi-accumulator CPU-side hash helper."""
    src = _read(os.path.join(PROJECT_ROOT, "Threading.cpp"))
    check("HashIoBufferForCpuPower" in src and
          "vacc0" in src and "vacc3" in src and
          src.count("HashIoBufferForCpuPower(p,") >= 2,
          "I/O shared multi-accumulator hash helper")


def test_invariant_perf_stats_initializes_cpu(binary):
    """--perf-stats must initialize CPU features and FPU flush mode before timing."""
    src = _read(os.path.join(PROJECT_ROOT, "ShaderStress.cpp"))
    check("g_Cpu = GetCpuInfo();" in src and
          "SetFpuFlushMode();" in src and
          "RunPerfStats();" in src,
          "--perf-stats initializes CPU features and FPU state")


def test_invariant_realistic_unchanged(binary):
    """RunRealisticCompilerSim_V3 is user-excluded and must remain source-stable."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    actual = _stable_source_hash(_extract_function(src, "RunRealisticCompilerSim_V3"))
    check(actual == "e7a0fcebe39e38cb1b0db368a7440dfef0cf9f648928d630046a24fa7ef14425",
          "RealisticCompilerSim_V3 source hash unchanged")


def test_invariant_decomp_idiv(binary):
    """DecompressLogic must inject 64-bit IDIV every 64 bytes (high-latency port-0 traffic)."""
    src = _read(os.path.join(PROJECT_ROOT, "Threading.cpp"))
    check("acc = acc / ((data[i] & 0xFFFFFFFFULL) | 1ULL)" in src,
          "DecompressLogic has 64-bit IDIV injection")


def test_invariant_lhm_subfolder(binary):
    """PawnIO setup path must reference lhm/ subfolder."""
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    check('L"lhm\\\\PawnIO_setup.exe"' in src,
          "PawnIO_setup.exe path uses lhm/ subfolder")


def test_invariant_lhm_build_copy(binary):
    """build.py must copy LHM to lhm/ subfolder, not flat."""
    build = _read(os.path.join(PROJECT_ROOT, "build.py"))
    check('"lhm"' in build and ('/ rel' in build or '/ name' in build),
          "build.py copies LHM to lhm/ subfolder")


def test_invariant_shutdown_power(binary):
    """ShutdownPowerMeasurement must be declared and called on cleanup."""
    hdr = _read(os.path.join(PROJECT_ROOT, "Common.h"))
    src = _read(os.path.join(PROJECT_ROOT, "Workloads.cpp"))
    main_src = _read(os.path.join(PROJECT_ROOT, "ShaderStress.cpp"))
    check("ShutdownPowerMeasurement" in hdr,
          "ShutdownPowerMeasurement declared in Common.h")
    check("void ShutdownPowerMeasurement()" in src,
          "ShutdownPowerMeasurement defined in Workloads.cpp")
    check("ShutdownPowerMeasurement()" in main_src,
          "ShutdownPowerMeasurement called in ShaderStress.cpp")


def test_invariant_power_logged(binary):
    """Power must be logged to ShaderStress.log during benchmarks."""
    src = _read(os.path.join(PROJECT_ROOT, "Threading.cpp"))
    check('L"Power: "' in src,
          "Power logging in Watchdog")


LIGHTWEIGHT_TESTS = [
    test_help,
    test_version,
    test_verify_invalid,
    test_verify_malformed,
    test_verify_empty,
    test_verify_bad_prefix,
    test_invalid_arg,
    test_missing_mode_value,
    test_invalid_mode_value,
    test_missing_isa_value,
    test_repro_with_benchmark_conflict,
    test_verify_with_mode_conflict,
    test_verify_with_wizard_conflict,
    test_verify_with_isa_conflict,
    test_modifier_without_action,
    test_duration_zero,
    test_max_duration_alias_validation,
    test_repro_missing_args,
    test_repro_partial_args,
    test_hash_roundtrip,
    test_invariant_synth_work_buf_elems,
    test_invariant_ram_stress_cap,
    test_invariant_decomp_passes,
    test_invariant_avx512_fma_permute_no_div_sqrt,
    test_invariant_avx2_fma_permute_no_div_sqrt,
    test_invariant_sse2_no_contract_no_div_sqrt,
    test_invariant_ram_full_stream_separate_chase,
    test_invariant_io_multi_accumulator_hash,
    test_invariant_perf_stats_initializes_cpu,
    test_invariant_decomp_idiv,
    test_invariant_realistic_unchanged,
    test_invariant_lhm_subfolder,
    test_invariant_lhm_build_copy,
    test_invariant_shutdown_power,
    test_invariant_power_logged,
]


# ---------------------------------------------------------------------------
# CPU-stressing tests (only run with --stress)
# ---------------------------------------------------------------------------

def test_repro_scalar(binary):
    ret, out, err = run(binary, ["--repro", "42", "100", "--isa", "scalar", "--quiet"])
    check(ret == 0, "--repro scalar")


def test_repro_scalar_sim(binary):
    ret, out, err = run(binary, ["--repro", "42", "100", "--isa", "scalar-sim", "--quiet"])
    check(ret == 0, "--repro scalar-sim")


def test_repro_avx2_if_available(binary):
    ret, out, err = run(binary, ["--repro", "42", "100", "--isa", "avx2", "--quiet"])
    check(ret == 0, "--repro avx2 quick")


def test_mode_steady_short(binary):
    ret, out, err = run(binary, ["--mode", "steady", "--isa", "scalar", "--duration", "3", "--quiet"])
    check(ret == 0, "--mode steady --duration 3")


def test_max_duration_alias_run(binary):
    ret, out, err = run(binary, ["--max-duration", "3", "--mode", "steady", "--isa", "scalar", "--quiet"])
    check(ret == 0, "--max-duration as --duration alias")


def record_golden_values(binary):
    golden = {}
    workloads = ["scalar", "scalar-sim"]
    for wl in workloads:
        ret, out, err = run(binary, ["--repro", "42", "1000", "--isa", wl, "--quiet"])
        golden[wl] = "ok" if ret == 0 else f"fail:{ret}"
    with open(GOLDEN_FILE, "w") as f:
        json.dump({"seed": 42, "complexity": 1000, "workloads": golden}, f, indent=2)
    print(f"  [INFO] Golden values saved to {GOLDEN_FILE}")


def verify_golden_values(binary):
    if not os.path.exists(GOLDEN_FILE):
        print("  [SKIP] golden values (no baseline file)")
        return
    with open(GOLDEN_FILE) as f:
        expected = json.load(f)
    for wl, status in expected.get("workloads", {}).items():
        if status == "ok":
            ret, out, err = run(binary, ["--repro", "42", "1000", "--isa", wl, "--quiet"])
            check(ret == 0, f"golden value: {wl}")
        else:
            print(f"  [SKIP] golden {wl}: no baseline")


STRESS_TESTS = [
    test_repro_scalar,
    test_repro_scalar_sim,
    test_repro_avx2_if_available,
    test_mode_steady_short,
    test_max_duration_alias_run,
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_with_sanitizer(mode="undefined"):
    """Build the native target with a sanitizer and return the binary path."""
    import subprocess as sp
    print(f"  [BUILD] Building with --sanitize={mode}")
    result = sp.run([sys.executable, "build.py", "--sanitize=" + mode, "native"],
                    capture_output=True, timeout=300, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"  [FAIL] sanitizer build ({mode}): {result.stderr.decode(errors='replace')[-200:]}")
        return None
    return find_binary()


def test_sanitizer_undefined(binary):
    """Run CLI tests under UBSan build (fast, no CPU stress)."""
    if not binary:
        return
    ret, out, err = run(binary, ["--help"])
    text = out.decode(errors="replace")
    check(ret == 0 and "Usage:" in text, "UBSan: --help")


def test_sanitizer_hash_roundtrip(binary):
    if not binary:
        return
    ret, out, err = run(binary, ["--hash-roundtrip"])
    text = out.decode(errors="replace")
    check(ret == 0 and "roundtrip OK" in text, "UBSan: --hash-roundtrip")


def main():
    global PASS, FAIL
    binary = find_binary()
    if not binary:
        print("ERROR: Could not find ShaderStress binary.")
        print("Build the project first: python build.py native")
        sys.exit(1)

    # Parse flags
    flags = set(sys.argv[1:])
    flags.discard("--bin")
    for i, a in enumerate(sys.argv):
        if a == "--bin" and i + 1 < len(sys.argv):
            binary = sys.argv[i + 1]
            flags.discard("--bin")

    run_stress = "--stress" in flags
    record_golden = "--record-golden" in flags
    run_sanitizer = "--sanitize" in flags

    if not os.path.exists(binary):
        print(f"ERROR: Binary not found: {binary}")
        sys.exit(1)

    print(f"Binary: {binary}")

    # Lightweight tests (always run)
    print(f"\n--- CLI tests ({len(LIGHTWEIGHT_TESTS)} tests) ---")
    for fn in LIGHTWEIGHT_TESTS:
        try:
            fn(binary)
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            FAIL += 1

    # CPU-stressing tests (only with --stress)
    if run_stress:
        print(f"\n--- Workload tests ({len(STRESS_TESTS)} tests) ---")
        for fn in STRESS_TESTS:
            try:
                fn(binary)
            except Exception as e:
                print(f"  [FAIL] {fn.__name__}: {e}")
                FAIL += 1
        print(f"\n--- Golden value checks ---")
        if record_golden:
            record_golden_values(binary)
        else:
            verify_golden_values(binary)
    else:
        print(f"\n  (use --stress to also run CPU workload tests)")

    # Sanitizer builds (only with --sanitize)
    if run_sanitizer:
        print(f"\n--- Sanitizer builds ---")
        san_binary = build_with_sanitizer("undefined")
        if san_binary:
            test_sanitizer_undefined(san_binary)
            test_sanitizer_hash_roundtrip(san_binary)
        else:
            print("  [SKIP] sanitizer tests (build failed)")

    total = PASS + FAIL
    print(f"\n{'='*50}")
    print(f"Passed: {PASS} / {total}" + ("  (no stress tests)" if not run_stress else ""))
    print(f"{'='*50}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
