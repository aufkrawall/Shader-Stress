#!/usr/bin/env python3
"""
ShaderStress test runner.

Default: lightweight tests only (CLI contract, source invariants, the in-binary
--self-test unit suite). Nothing here starts the multi-threaded stress run.

    python tests/run_tests.py                          # lightweight tests
    python tests/run_tests.py --stress                 # + short low-thread smoke runs and golden checksums
    python tests/run_tests.py --sanitize               # + UBSan and ASan builds running --self-test
    python tests/run_tests.py --stress --record-golden # re-record golden checksums (after intended kernel changes)
    python tests/run_tests.py --bin <path>             # use a specific binary
"""

import glob
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock
import contextlib
import io

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN_FILE = os.path.join(os.path.dirname(__file__), "golden_values.json")
IS_WINDOWS = sys.platform == "win32"
EXE = "ShaderStress.com" if IS_WINDOWS else "shaderstress"

# Smoke runs must stay light: few threads, tiny RAM/IO footprints, seconds.
LIGHT = ["--threads", "2", "--ram-mb", "64", "--io-mb", "16", "--quiet"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_binary():
    for rel in ("x64-llvm", "x64-llvm-v3", "linux-x64", "linux-arm64", "macos-arm64"):
        c = os.path.join(PROJECT_ROOT, "bin", rel, EXE)
        if os.path.exists(c):
            return c
    matches = glob.glob(os.path.join(PROJECT_ROOT, "bin", "**", EXE), recursive=True)
    matches = [m for m in matches if not re.search(r"-(ubsan|asan|tsan)", m)]
    return matches[0] if matches else None


# Binaries write ShaderStress.log / Crash_* into their working directory; keep
# those out of the repo root.
WORK_DIR = os.path.join(PROJECT_ROOT, "bin", "test-work")


def run(binary, args, timeout=60):
    os.makedirs(WORK_DIR, exist_ok=True)
    try:
        r = subprocess.run([binary] + args, capture_output=True, timeout=timeout, cwd=WORK_DIR)
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", "FILE NOT FOUND"


PASS = 0
FAIL = 0


def check(ok, msg, detail=""):
    global PASS, FAIL
    if ok:
        print(f"  [OK] {msg}")
        PASS += 1
    else:
        print(f"  [FAIL] {msg}" + (f"\n         {detail.strip()[:600]}" if detail else ""))
        FAIL += 1


def _read(name):
    with open(os.path.join(PROJECT_ROOT, name), "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _extract_function(src, name):
    start = src.index(f"uint64_t {name}")
    brace = src.index("{", start)
    depth = 0
    for pos in range(brace, len(src)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                return src[start:pos + 1]
    raise ValueError(f"function not closed: {name}")


def _stable_source_hash(text):
    normalized = "\n".join(line.rstrip() for line in text.splitlines())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def arch_key():
    m = platform.machine().lower()
    return "arm64" if ("arm" in m or "aarch64" in m) else "x64"


# ---------------------------------------------------------------------------
# Lightweight CLI contract tests
# ---------------------------------------------------------------------------

def test_help(b):
    ret, out, _ = run(b, ["--help"])
    check(ret == 0 and "Usage:" in out and "--mode" in out and "corecycle" in out and
          "--threads" in out and "--self-test" in out, "--help lists modes and new options")


def test_version(b):
    ret, out, _ = run(b, ["--version"])
    version = _read("VERSION").strip()
    check(ret == 0 and f"ShaderStress {version}" in out, "--version matches VERSION file", out)


def test_self_test(b):
    ret, out, err = run(b, ["--self-test"], timeout=120)
    check(ret == 0 and "ALL PASSED" in out and "[FAIL]" not in out, "--self-test unit suite",
          out[-1500:] + err)


def test_hash_roundtrip(b):
    ret, out, _ = run(b, ["--hash-roundtrip"])
    check(ret == 0 and "roundtrip OK" in out, "--hash-roundtrip")


INVALID_ARGS = [
    (["--verify", "SS3-0000000000000000"], 4, "INVALID", "--verify invalid hash"),
    (["--verify", "not-a-hash"], 4, None, "--verify malformed"),
    (["--verify", ""], 4, None, "--verify empty"),
    (["--verify", "XX3-0000000000000000"], 4, None, "--verify bad prefix"),
    (["--nonexistent"], 2, None, "unknown option"),
    (["--mode"], 2, None, "--mode missing value"),
    (["--mode", "invalid", "--duration", "1"], 2, None, "--mode invalid value"),
    (["--isa"], 2, None, "--isa missing value"),
    (["--repro", "1", "1", "--benchmark"], 2, None, "--repro + --benchmark"),
    (["--verify", "SS3-0000000000000000", "--mode", "steady"], 2, None, "--verify + --mode"),
    (["--verify", "SS3-0000000000000000", "--wizard"], 2, None, "--verify + --wizard"),
    (["--verify", "SS3-0000000000000000", "--isa", "avx2"], 2, None, "--verify + --isa"),
    (["--verify", "SS3-0000000000000000", "--no-ram"], 2, None, "--verify + --no-ram"),
    (["--no-avx512"], 2, None, "modifier without action"),
    (["--threads", "4"], 2, None, "--threads without action"),
    (["--duration", "0"], 2, None, "--duration 0"),
    (["--max-duration", "0"], 2, None, "--max-duration 0"),
    (["--repro"], 2, None, "--repro missing args"),
    (["--repro", "1"], 2, None, "--repro partial args"),
    (["--repro", "1", "0"], 2, None, "--repro complexity 0"),
    (["--repro", "1", "60000000"], 2, None, "--repro complexity above limit"),
    (["--repro", "1", "10", "--threads", "2"], 2, None, "--repro + --threads"),
    (["--repro", "1", "10", "--no-decompress"], 2, None, "--repro + --no-decompress"),
    (["--no-decompress"], 2, None, "--no-decompress without action"),
    (["--mode", "steady", "--threads", "0", "--duration", "1"], 2, None, "--threads 0"),
    (["--mode", "steady", "--threads", "x", "--duration", "1"], 2, None, "--threads non-numeric"),
    (["--mode", "steady", "--dwell", "5", "--duration", "1"], 2, None, "--dwell outside corecycle"),
    (["--mode", "corecycle", "--dwell", "0", "--duration", "1"], 2, None, "--dwell 0"),
    (["--mode", "steady", "--ram-mb", "8", "--duration", "1"], 2, None, "--ram-mb below minimum"),
    (["--mode", "steady", "--io-mb", "1", "--duration", "1"], 2, None, "--io-mb below minimum"),
    (["--mode", "benchmark", "--duration", "60"], 2, None, "benchmark with custom duration"),
    (["--power-window", "23"], 2, None, "power window needs explicit benchmark mode"),
    (["--mode", "steady", "--power-window", "23"], 2, None, "power window rejects steady mode"),
    (["--mode", "benchmark", "--power-window", "24"], 2, None, "power window above 23 s"),
    (["--mode", "benchmark", "--power-window", "0"], 2, None, "power window zero duration"),
    (["--mode", "benchmark", "--power-window"], 2, None, "power window missing duration"),
    (["--mode", "benchmark", "--power-window", "23", "--duration", "180"], 2, None, "power window conflicting duration"),
    (["--mode", "benchmark", "--power-window", "23", "--wizard"], 2, None, "power window conflicting wizard"),
    (["--mode", "benchmark", "--power-window", "23", "--self-test"], 2, None, "power window conflicting diagnostics"),
    (["--benchmark", "--mode", "steady"], 2, None, "--benchmark + other mode"),
]


def test_invalid_args(b):
    for args, code, needle, name in INVALID_ARGS:
        ret, out, err = run(b, args)
        ok = ret == code and (needle is None or needle in out + err)
        check(ok, f"{name} -> exit {code}", f"exit {ret}: {out}{err}")


# ---------------------------------------------------------------------------
# Source-invariant regression tests (read-only)
# ---------------------------------------------------------------------------

def test_invariant_realistic_unchanged(b):
    """RunRealisticCompilerSim_V3 is user-pinned. Only change: 3.6.0 masked the
    rotate's right-shift count (`>> 64` was UB when src2 & 63 == 0; found by
    UBSan). Output is bit-identical (golden checksum 0x58b1a15ca01f7216)."""
    src = _read("src/workloads/WorkloadRealistic.cpp")
    actual = _stable_source_hash(_extract_function(src, "RunRealisticCompilerSim_V3"))
    check(actual == "02290c1a756fd7099c973a4ea1662617c8fb92200ac9f26fcf6c477c2ffb3270",
          "RealisticCompilerSim_V3 source hash unchanged", actual)


def test_invariant_kernels_unitary_bounded(b):
    """Synthetic kernels: unitary butterflies (|w| == k), no inf-prone growth."""
    hdr = _read("src/workloads/Workloads.h")
    inc = _read("src/workloads/SynthKernel.inc")
    m_re = re.search(r"SYNTH_TW_RE = ([0-9.e-]+);", hdr)
    m_im = re.search(r"SYNTH_TW_IM = ([0-9.e-]+);", hdr)
    m_k = re.search(r"SYNTH_SCALE = ([0-9.e-]+);", hdr)
    ok = bool(m_re and m_im and m_k)
    if ok:
        wr, wi, k = float(m_re.group(1)), float(m_im.group(1)), float(m_k.group(1))
        ok = abs((wr * wr + wi * wi) - 0.5) < 1e-15 and abs(k * k - 0.5) < 1e-15
    old_growth = "1.000001" in _read("src/workloads/SynthKernels.cpp") + inc
    check(ok and not old_growth and "SK_BFLY_CONJ" in inc and "SK_STORE(pa, ar)" in inc,
          "synthetic kernels are unitary (bounded, error-preserving)")


def test_invariant_kernels_preemptible_and_strict_fp(b):
    inc = _read("src/workloads/SynthKernel.inc")
    k = _read("src/workloads/SynthKernels.cpp") + _read("src/workloads/SynthKernelsX86.cpp")
    build = _read("build.py")
    check("StopRequested()" in inc and k.count("#pragma clang fp contract(off)") >= 3 and
          '"-ffast-math"' not in build and "NOINLINE uint64_t RunComputeWorkload" in k,
          "kernels preemptible, contract(off), no -ffast-math, single dispatch body")


def test_invariant_paired_verification(b):
    worker = _read("src/engine/Worker.cpp")
    check("GlobalPairTable().Submit" in worker and "ResolveMismatch" in worker and
          "g_Golden.values[type]" in worker and "RunDecompressJob" in worker,
          "every compute job paired + golden checks + verified decompression")


def test_invariant_event_driven_scheduler(b):
    sched = _read("src/engine/Scheduler.cpp")
    worker = _read("src/engine/Worker.cpp")
    check("s_workCv.wait" in sched and "sleep_for(1ms)" not in worker and
          "s_auxCv.wait" in sched and "WorkerSlotForCoreRank" in _read("src/core/Topology.h"),
          "workers/testers wake on events (no idle polling), topology-aware slots")


def test_invariant_ram_io_verified(b):
    ram = _read("src/engine/RamStress.cpp")
    io = _read("src/engine/IoStress.cpp")
    check("VerifyPattern" in ram and "RandomVerify" in ram and "16ull << 30" in ram and
          "VerifyIoChunk" in io and "FILE_FLAG_NO_BUFFERING" in io and "O_DIRECT" in io,
          "RAM and I/O testers verify every word (70%/16 GiB default RAM size)")


def test_invariant_build_sanitizer_and_symbols(b):
    build = _read("build.py")
    check("global PGO_MODE, SANITIZER_MODE" in build and "SANITIZER_SUFFIX" in build and
          "--pdb=" in build and "--only-keep-debug" in build,
          "build.py: sanitizer flag takes effect, separate dirs, debug symbols emitted")


def host_has(feature_id):
    """Windows IsProcessorFeaturePresent (40 = AVX2, 41 = AVX-512F); None if unknown."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(feature_id))
    except Exception:
        return None


def test_cpu_level_guard(b):
    """v3/v4 builds must refuse unsupported CPUs with a message (exit 3), not crash
    with an illegal instruction inside a static initializer."""
    for rel, feature in (("x64-llvm-v4", 41), ("x64-llvm-v3", 40)):
        exe = os.path.join(PROJECT_ROOT, "bin", rel, EXE)
        has = host_has(feature)
        if not os.path.exists(exe) or has is None:
            print(f"  [SKIP] cpu guard {rel} (binary or host feature info unavailable)")
            continue
        ret, out, err = run(exe, ["--version"])
        if has:
            check(ret == 0 and "ShaderStress" in out, f"cpu guard {rel}: supported CPU starts", out + err)
        else:
            check(ret == 3 and "requires an x86-64-v" in err, f"cpu guard {rel}: clear refusal",
                  f"exit {ret}: {out}{err}")
    build = _read("build.py")
    check("GUARD_ENTRY" in build and "constructor(101)" in _read("src/core/CpuGuard.cpp"),
          "cpu guard wired into build (PE entry / ELF constructor)")


def test_invariant_lhm(b):
    power = _read("src/core/PowerMeasure.cpp")
    hdr = _read("src/core/Common.h")
    main_src = _read("src/app/CliRun.cpp")
    check('L"lhm\\\\PawnIO_setup.exe"' in power and "ShutdownPowerMeasurement" in hdr and
          "ShutdownPowerMeasurement()" in main_src and 'L"Power sample: elapsed_ms="' in power and
          "FormatPowerSampleLog(power, " in _read("src/engine/Watchdog.cpp") and
          "TakePowerSamples(&dropped)" in _read("src/engine/Watchdog.cpp") and
          'L"PowerReader.exe --stream "' in power and "args[0] != \"--stream\"" in _read("vendor/lhm/PowerReader.cs") and
          "ParsePowerReaderOutput(line.c_str(), sample)" in power and '"lhm"' in _read("build.py"),
          "LHM power readout wiring (lhm/ subfolder, 1 s stream, every reading logged, shutdown, parser)")


def test_invariant_file_sizes(b):
    """AGENTS.md: keep source files roughly <= 800 lines."""
    too_big = []
    for f in glob.glob(os.path.join(PROJECT_ROOT, "src", "**", "*.*"), recursive=True):
        if not f.endswith((".cpp", ".h", ".inc", ".c")):
            continue
        with open(f, encoding="utf-8", errors="replace") as fh:
            n = sum(1 for _ in fh)
        if n > 800:
            too_big.append(f"{os.path.basename(f)}={n}")
    check(not too_big, "source files <= 800 lines", ", ".join(too_big))


def test_invariant_repo_layout(b):
    """Sources live under src/<area>/, scripts/docs/resources in their folders."""
    stray = [f for f in os.listdir(PROJECT_ROOT)
             if f.endswith((".cpp", ".h", ".inc", ".c", ".rc", ".ico", ".ps1"))]
    needed = ["src/core/Common.h", "src/workloads/Workloads.h", "src/engine/Scheduler.h",
              "src/app/Cli.h", "src/launcher/cli_launcher.c", "resources/resource.rc",
              "docs/cli.md", "scripts/sweep_power.ps1", "lhm-deps/SHA256SUMS.txt"]
    missing = [n for n in needed if not os.path.exists(os.path.join(PROJECT_ROOT, n))]
    check(not stray and not missing, "repository layout (no stray root sources)",
          f"stray={stray} missing={missing}")


def test_build_comparisons(b):
    sys.path.insert(0, PROJECT_ROOT) if PROJECT_ROOT not in sys.path else None
    import build
    from scripts import build_kernels, build_msvc
    from scripts.build_options import select_configs
    base = set(build.common_cxx_flags("bin/x64-llvm-v3"))
    nounroll = set(build.common_cxx_flags("bin/x64-llvm-v3-nounroll"))
    alias_off = set(build.common_cxx_flags("bin/x64-llvm-v3-strictalias-off"))
    zen = set(build.common_cxx_flags("bin/x64-llvm-v3-znver3"))
    interleave1 = set(build.common_cxx_flags("bin/x64-llvm-v3-interleave1"))
    check(base - nounroll == {"-funroll-loops"} and not nounroll - base and
          alias_off - base == {"-fno-strict-aliasing"} and not base - alias_off and
          zen - base == {"-mtune=znver3"} and
          interleave1 - base == {"-mllvm", "-force-vector-interleave=1"} and
          not base - interleave1, "comparison flags vary one setting at a time")
    check(any(c[0].endswith("-msvc") for c in select_configs(["all"])) and
          select_configs(["msvc"]) == select_configs(["x64-msvc-v3"]) and
          len(select_configs(["win-v3", "win-v3"])) == 1, "MSVC default/explicit targets and deduplication")
    with mock.patch.object(build, "BUILD_OUTPUT_SUFFIX", "-tuning"):
        check(build.effective_out_dir("bin/x64-llvm-v3") == "bin/x64-llvm-v3-tuning" and
              set(build.common_cxx_flags("bin/x64-llvm-v3-nounroll-tuning")) == nounroll,
              "tuning outputs isolated; compiler comparisons preserved")
    completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
    with mock.patch("scripts.build_kernels.subprocess.run", return_value=completed) as run_compile:
        sources, warnings = build_kernels.compile_kernels(
            ["clang", "-O3", "-flto", "-g", "-fsanitize=undefined"],
            list(build.SRC_COMMON), Path(WORK_DIR), Path(PROJECT_ROOT))
        commands = [c.args[0] for c in run_compile.call_args_list]
        check(len(commands) == 2 and all("-fno-slp-vectorize" in c and "-flto" not in c and
              "-ffp-contract=off" in c and "-fsanitize=undefined" in c for c in commands) and
              "src/workloads/WorkloadRealistic.cpp" in sources and not warnings,
              "only synthetic objects isolated; sanitizers/strict FP preserved")
    for profile in ("-fprofile-generate", "-fprofile-use=fixture.profdata"):
        command = ["clang", "-O3", "-flto", "-g", profile]
        with mock.patch("scripts.build_kernels.subprocess.run", return_value=completed) as run_compile:
            sources, warnings = build_kernels.compile_kernels(
                command, list(build.SRC_COMMON), Path(WORK_DIR), Path(PROJECT_ROOT))
            commands = [c.args[0] for c in run_compile.call_args_list]
            check(len(commands) == 2 and all(profile not in c and "-g" in c and
                  "-O3" in c and "-ffp-contract=off" in c and "-fno-lto" in c for c in commands) and
                  profile in command and "src/workloads/WorkloadRealistic.cpp" in sources and
                  not warnings, "PGO stays on main/realistic code, native kernels unchanged: " + profile)
    config = ("x86_64-windows-msvc", "bin/test-work/msvc-plan", "x86_64_v3", True, "", False)
    with mock.patch.object(build_msvc, "discover", return_value=({}, {k: k for k in ("cl", "link", "rc")})), \
         mock.patch("scripts.build_msvc.subprocess.run", return_value=completed) as compile_msvc, \
         mock.patch.object(build, "set_pe_checksum"), mock.patch.object(build, "build_power_reader"):
        result = build_msvc.build(config, build)
        commands = [c.args[0] for c in compile_msvc.call_args_list]
        guard = next(c for c in commands if "src/core/CpuGuard.cpp" in c)
        wide = next(c for c in commands if "src/workloads/SynthKernelsX86.cpp" in c)
        check(result[0] and "/GL-" in guard and not any(c.startswith("/arch:") for c in guard) and
              "/arch:AVX2" in wide and "/GL-" in wide and "/fp:strict" in wide and
              not any("/arch:AVX512" in c for c in commands) and
              any("/entry:ShaderStressGuardedEntry" in c for c in commands),
              "MSVC: baseline guard, one /arch:AVX2 for all objects (no AVX-512 COMDAT leak), strict FP")
        check(not result[3], "MSVC comparison build is never packaged")


def test_default_build_is_best_variant(b):
    """Promotion rule (user instruction 2026-10-06): build.py's defaults always
    compile the measured-best variant. Every accepted power setting lives in the
    default flag set / kernel-object flags / Workloads.h knob defaults, and no
    A/B-variant-only setting does. Comparison variants stay single-setting arms
    and get promoted into the defaults when they win (power-ledger)."""
    sys.path.insert(0, PROJECT_ROOT) if PROJECT_ROOT not in sys.path else None
    import build
    accepted = {"-O3", "-funroll-loops", "-fstrict-aliasing", "-fno-stack-protector",
                "-fomit-frame-pointer", "-fno-math-errno"}
    forbidden = {"-ffast-math", "-fno-strict-aliasing", "-fno-unroll-loops",
                 "-funroll-all-loops", "-mtune=znver3", "-force-vector-interleave=1"}
    for out_dir in ("bin/x64-llvm", "bin/x64-llvm-v3", "bin/x64-zig", "bin/x64-zig-v3"):
        flags = set(build.common_cxx_flags(out_dir))
        check(accepted <= flags and not (flags & forbidden) and
              not any(f.startswith(("-mtune=", "-fprofile")) for f in flags),
              "default flags are the measured-best set: " + out_dir, " ".join(sorted(flags)))
    check(build.release_lto("bin/x64-llvm-v3") and build.release_lto("bin/x64-zig-v3") and
          not build.release_lto("bin/x64-llvm-v3-nolto") and
          not build.release_lto("bin/macos-x64", macos=True),
          "LTO on in defaults (P007b kept), off only for A/B arms and Apple targets")
    hdr = _read("src/workloads/Workloads.h")
    check(re.search(r"#define SYNTH_BUF_KIB 512\b", hdr) is not None and
          re.search(r"#define SYNTH_ROUNDS 1\b", hdr) is not None,
          "synthetic knob defaults are the measured winners (512 KiB x 1 round: P003/P011)")
    check("j ^ (kVecs / 2)" in _read("src/workloads/SynthKernel.inc"),
          "P045 far-swap streaming fill is part of the default kernels")


def test_kernel_codegen(b):
    """Static disassembly only. SLP used to pack the integer chains into vector
    registers, spilling ymm/zmm in the hot loop (and adding ymm integer work to
    the 128-bit kernel); each synthetic kernel must keep 8 explicit FMAs (wide
    kernels), its one 64-bit divide and no 256/512-bit stack traffic."""
    if not (IS_WINDOWS and arch_key() == "x64"):
        return
    sys.path.insert(0, PROJECT_ROOT) if PROJECT_ROOT not in sys.path else None
    from scripts import kernel_codegen
    tools = kernel_codegen.llvm_tools()
    if tools is None:
        print("  (skip kernel codegen audit: llvm-pdbutil/llvm-objdump not installed)")
        return
    checked = 0
    for build in kernel_codegen.DEFAULT_BUILDS:
        exe = os.path.join(PROJECT_ROOT, "bin", build, "ShaderStress.exe")
        if not (os.path.exists(exe) and os.path.exists(exe[:-4] + ".pdb")):
            continue
        report = kernel_codegen.analyze(Path(exe), tools)
        widest = {"SynthKernel128": "xmm", "SynthKernelAVX2": "ymm", "SynthKernelAVX512": "zmm"}
        for name, expect in widest.items():
            r = report.get(name)
            ok = (r is not None and not r["spills"] and r["div"] == 1 and r["widest"] == expect and
                  (name == "SynthKernel128" or r["fma"] == 8))
            check(ok, f"{build} {name}: explicit SIMD only, no wide spills",
                  str({k: v for k, v in (r or {}).items() if k != "spills"}) +
                  (" " + "; ".join(r["spills"][:3]) if r else ""))
        checked += 1
    check(checked > 0, "kernel codegen audit covered at least one built x64 binary")


def test_power_measurement(b):
    # Pure tooling tests (tests/power_tool_tests.py): no workload, no UAC elevation.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from power_tool_tests import run_power_tool_tests
    run_power_tool_tests(check)


LIGHTWEIGHT_TESTS = [
    test_build_comparisons,
    test_default_build_is_best_variant,
    test_kernel_codegen,
    test_power_measurement,
    test_help,
    test_version,
    test_self_test,
    test_hash_roundtrip,
    test_invalid_args,
    test_invariant_realistic_unchanged,
    test_invariant_kernels_unitary_bounded,
    test_invariant_kernels_preemptible_and_strict_fp,
    test_invariant_paired_verification,
    test_invariant_event_driven_scheduler,
    test_invariant_ram_io_verified,
    test_invariant_build_sanitizer_and_symbols,
    test_invariant_lhm,
    test_invariant_file_sizes,
    test_cpu_level_guard,
    test_invariant_repo_layout,
]


# ---------------------------------------------------------------------------
# Short, low-thread smoke runs (only with --stress)
# ---------------------------------------------------------------------------

def _repro(b, isa, complexity=100):
    return run(b, ["--repro", "42", str(complexity), "--isa", isa])


def test_repro_all_isas(b):
    for isa in ("scalar", "scalar-sim", "avx2", "avx512"):
        ret, out, err = _repro(b, isa)
        check(ret == 0 and "re-run matches" in out and "Result: 0x" in out,
              f"--repro {isa} (run twice, compare)", out + err)


def _smoke(b, name, args, timeout=60):
    ret, out, err = run(b, args + LIGHT, timeout=timeout)
    ok = ret == 0 and re.search(r"Errors: 0 \(CPU 0, RAM 0, I/O 0\)", out) is not None
    check(ok, name, out + err)
    return out


def test_smoke_steady(b):
    out = _smoke(b, "steady 3 s (2 threads, 64 MiB RAM, 16 MiB I/O)",
                 ["--mode", "steady", "--duration", "3"])
    check(re.search(r"Verified: [1-9]\d* job pairs", out) is not None and "I/O 0 B" not in out,
          "steady run verifies job pairs and I/O data", out)


def test_smoke_dynamic(b):
    _smoke(b, "dynamic 3 s (2 threads)", ["--mode", "dynamic", "--duration", "3"])


def test_smoke_corecycle(b):
    out = _smoke(b, "corecycle 3 s (1 s dwell)", ["--mode", "corecycle", "--dwell", "1",
                                                  "--duration", "3"])
    check(re.search(r"[1-9]\d* golden checks", out) is not None,
          "corecycle runs frequent golden checks", out)


def test_smoke_no_ram_no_io(b):
    out = _smoke(b, "steady with --no-ram --no-io", ["--mode", "steady", "--duration", "2",
                                                     "--no-ram", "--no-io"])
    check("RAM 0 B, I/O 0 B" in out, "--no-ram/--no-io honoured", out)


def test_smoke_compute_only(b):
    out = _smoke(b, "steady compute-only (--no-decompress --no-ram --no-io)",
                 ["--mode", "steady", "--duration", "2", "--no-ram", "--no-io", "--no-decompress"])
    check(" 0 decompression passes" in out and re.search(r"Verified: [1-9]", out) is not None,
          "--no-decompress turns decompressors into compute workers", out)


def golden_checksums(b):
    result = {}
    for isa in ("scalar", "scalar-sim", "avx2"):
        ret, out, _ = _repro(b, isa, 1000)
        m = re.search(r"Result: (0x[0-9a-f]{16})", out)
        result[isa] = m.group(1) if ret == 0 and m else f"fail:{ret}"
    return result


def record_golden_values(b):
    data = {}
    if os.path.exists(GOLDEN_FILE):
        with open(GOLDEN_FILE) as f:
            data = json.load(f)
    data.setdefault("checksums", {})[arch_key()] = golden_checksums(b)
    data["seed"], data["complexity"] = 42, 1000
    data.pop("workloads", None)
    with open(GOLDEN_FILE, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"  [INFO] Golden checksums saved to {GOLDEN_FILE}: {data['checksums'][arch_key()]}")


def verify_golden_values(b):
    """Kernel results are bit-exact IEEE across builds of one architecture; a
    change means the kernel (or codegen semantics) changed."""
    if not os.path.exists(GOLDEN_FILE):
        print("  [SKIP] golden checksums (no baseline file)")
        return
    with open(GOLDEN_FILE) as f:
        expected = json.load(f).get("checksums", {}).get(arch_key())
    if not expected:
        print(f"  [SKIP] golden checksums (no baseline for {arch_key()})")
        return
    actual = golden_checksums(b)
    for isa, value in expected.items():
        check(actual.get(isa) == value, f"golden checksum {isa}", f"expected {value} got {actual.get(isa)}")


STRESS_TESTS = [
    test_repro_all_isas,
    test_smoke_steady,
    test_smoke_dynamic,
    test_smoke_corecycle,
    test_smoke_no_ram_no_io,
    test_smoke_compute_only,
]


# ---------------------------------------------------------------------------
# Sanitizer builds (only with --sanitize)
# ---------------------------------------------------------------------------

def build_with_sanitizer(mode):
    target = "win-baseline" if IS_WINDOWS else "native"
    print(f"  [BUILD] python build.py --sanitize={mode} {target}")
    r = subprocess.run([sys.executable, "build.py", f"--sanitize={mode}", target],
                       capture_output=True, timeout=900, cwd=PROJECT_ROOT)
    out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    suffix = {"undefined": "-ubsan", "address": "-asan"}[mode]
    pattern = os.path.join(PROJECT_ROOT, "bin", f"*{suffix}", EXE)
    found = glob.glob(pattern)
    check(r.returncode == 0 and bool(found), f"sanitizer build ({mode})", out[-1500:])
    return found[0] if found else None


def run_sanitized_suite(b, label):
    ret, out, err = run(b, ["--self-test"], timeout=600)
    check(ret == 0 and "ALL PASSED" in out, f"{label}: --self-test", out[-1500:] + err[-1500:])
    ret, out, err = run(b, ["--hash-roundtrip"])
    check(ret == 0 and "roundtrip OK" in out, f"{label}: --hash-roundtrip", err)
    for isa in ("scalar", "scalar-sim", "avx2"):
        ret, out, err = run(b, ["--repro", "7", "20", "--isa", isa, "--quiet"], timeout=300)
        check(ret == 0, f"{label}: --repro {isa}", out + err)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global PASS, FAIL
    args = sys.argv[1:]
    binary = None
    if "--bin" in args:
        i = args.index("--bin")
        if i + 1 < len(args):
            binary = args[i + 1]
    binary = binary or find_binary()
    if binary:
        binary = os.path.abspath(binary)
    if not binary or not os.path.exists(binary):
        print("ERROR: Could not find ShaderStress binary. Build first: python build.py native")
        return 1
    run_stress = "--stress" in args
    print(f"Binary: {binary}")

    print(f"\n--- Lightweight tests ---")
    for fn in LIGHTWEIGHT_TESTS:
        try:
            fn(binary)
        except Exception as e:
            check(False, fn.__name__, repr(e))

    if run_stress:
        print(f"\n--- Smoke runs (low thread count, seconds) ---")
        for fn in STRESS_TESTS:
            try:
                fn(binary)
            except Exception as e:
                check(False, fn.__name__, repr(e))
        print(f"\n--- Golden checksums ---")
        if "--record-golden" in args:
            record_golden_values(binary)
        else:
            verify_golden_values(binary)
            if IS_WINDOWS and arch_key() == "x64" and host_has(40):
                for variant in ("x64-llvm-v3", "x64-zig-v3", "x64-msvc-v3"):
                    candidate = os.path.join(PROJECT_ROOT, "bin", variant, EXE)
                    if os.path.exists(candidate) and os.path.abspath(candidate) != os.path.abspath(binary):
                        print(f"\n--- Compiler comparison: {variant} ---")
                        test_self_test(candidate)
                        verify_golden_values(candidate)
    else:
        print(f"\n  (use --stress to also run short smoke runs)")

    if "--sanitize" in args:
        print(f"\n--- Sanitizer builds ---")
        for mode, label in (("undefined", "UBSan"), ("address", "ASan")):
            san = build_with_sanitizer(mode)
            if san:
                run_sanitized_suite(san, label)

    total = PASS + FAIL
    print(f"\n{'=' * 50}\nPassed: {PASS} / {total}\n{'=' * 50}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
