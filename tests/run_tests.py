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
    test_mode_steady_short,
    test_max_duration_alias_run,
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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

    total = PASS + FAIL
    print(f"\n{'='*50}")
    print(f"Passed: {PASS} / {total}" + ("  (no stress tests)" if not run_stress else ""))
    print(f"{'='*50}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
