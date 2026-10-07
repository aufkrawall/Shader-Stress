#!/usr/bin/env python3
"""
ShaderStress Build Script
Windows: LLVM MinGW (clang++ / lld) and Zig
Linux/macOS: Zig cross-compilation
"""
import os
import sys
import subprocess
import shutil
import multiprocessing
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import urllib.request
from scripts.build_options import (CPU_ARCH_MAP, MINGW_ARCH_MAP,
                                   print_help, select_configs)
from scripts import build_msvc, build_kernels

# Configuration
BASE_DIR = Path(__file__).resolve().parent
LHM_DEPS_URL = "https://raw.githubusercontent.com/aufkrawall/Shader-Stress/main/lhm-deps"
LHM_DEPS_FILES = [
    "LibreHardwareMonitorLib.dll",
    "PawnIO_setup.exe",
    "System.Memory.dll",
    "System.Buffers.dll",
    "System.Runtime.CompilerServices.Unsafe.dll",
    "LICENSE-MPL-2.0.txt",
    "NOTICE.txt",
]
SRC_DIR = BASE_DIR / "src"
RESOURCE_RC = BASE_DIR / "resources" / "resource.rc"
CLI_LAUNCHER_SOURCE = SRC_DIR / "launcher" / "cli_launcher.c"
VERSION_FILE = BASE_DIR / "VERSION"


def toolchain_dir(*parts):
    """Toolchains live (git-ignored) under toolchains/; the repo root is a fallback
    for older checkouts that extracted them there."""
    preferred = BASE_DIR / "toolchains" / Path(*parts)
    legacy = BASE_DIR / Path(*parts)
    return preferred if preferred.exists() or not legacy.exists() else legacy


ZIG_DIR = toolchain_dir("zig-x86_64-windows-0.15.2")
ZIG_EXE = ZIG_DIR / "zig.exe"
LLVM_MINGW_DIR = toolchain_dir("llvm-mingw-20260519-ucrt-x86_64", "llvm-mingw-20260519-ucrt-x86_64")
LLVM_MINGW_BIN = LLVM_MINGW_DIR / "bin"
LLVM_OBJCOPY = LLVM_MINGW_BIN / "llvm-objcopy.exe"

# Extra preprocessor defines forwarded to every compile, taken from the
# SHADERSTRESS_EXTRA_DEFINES environment variable (space separated). Used by
# scripts/sweep_power.ps1 to override the kernel tuning knobs in src/workloads/Workloads.h
# (e.g. SHADERSTRESS_EXTRA_DEFINES="-DSYNTH_BUF_KIB=256 -DSYNTH_ROUNDS=3").
EXTRA_DEFINES = os.environ.get("SHADERSTRESS_EXTRA_DEFINES", "").split()


def log(msg):
    print(f"[BUILD] {msg}", flush=True)


def load_version():
    """Load version metadata from VERSION"""
    if not VERSION_FILE.exists():
        log(f"ERROR: VERSION file not found at {VERSION_FILE}")
        sys.exit(1)
    version_text = VERSION_FILE.read_text(encoding="utf-8").strip()
    parts = version_text.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        log(f"ERROR: Invalid version string '{version_text}' in VERSION")
        sys.exit(1)
    major, minor, patch = (int(part) for part in parts)
    return version_text, major, minor, patch


# Source files (relative to the repo root; headers are included as "<dir>/<file>.h"
# with -Isrc).
SRC_COMMON = [
    "src/core/Common.cpp", "src/core/CpuFeatures.cpp", "src/core/Topology.cpp",
    "src/core/Platform.cpp", "src/core/PowerMeasure.cpp", "src/core/CpuGuard.cpp",
    "src/workloads/SynthKernels.cpp", "src/workloads/SynthKernelsX86.cpp",
    "src/workloads/WorkloadRealistic.cpp", "src/workloads/WorkloadRealisticV5.cpp",
    "src/workloads/WorkloadRealisticV5Corpus.cpp", "src/workloads/WorkloadRealisticV5Encode.cpp",
    "src/workloads/WorkloadRealisticV5Front.cpp",
    "src/workloads/WorkloadRealisticV5Opt.cpp", "src/workloads/WorkloadRealisticV5Fold.cpp",
    "src/workloads/WorkloadRealisticV5Lower.cpp",
    "src/workloads/WorkloadRealisticV5Back.cpp",
    "src/workloads/Decompress.cpp",
    "src/engine/Verification.cpp", "src/engine/Worker.cpp", "src/engine/Scheduler.cpp",
    "src/engine/Watchdog.cpp", "src/engine/RamStress.cpp", "src/engine/IoStress.cpp",
    "src/app/CliArgs.cpp", "src/app/CliRun.cpp", "src/app/SelfTest.cpp",
    "src/app/ShaderStress.cpp",
]

# Windows v3/v4 builds start in CpuGuard.cpp, which verifies the CPU supports the
# build's ISA level before the CRT and static constructors run.
GUARDED_CPUS = ("x86_64_v3", "x86_64_v4")
GUARD_ENTRY = "ShaderStressGuardedEntry"
SRC_FILES_WINDOWS = SRC_COMMON + ["src/app/Gui.cpp"]
SRC_FILES_UNIX = SRC_COMMON + ["src/app/TerminalUtils.cpp"]

APP_VERSION_TEXT, APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH = load_version()

# PGO mode: None, "generate", or "use"
PGO_MODE = None
# Sanitizer mode: None, "undefined", "address", or "thread"
SANITIZER_MODE = None
BUILD_OUTPUT_SUFFIX = ""
SANITIZER_SUFFIX = {"undefined": "-ubsan", "address": "-asan", "thread": "-tsan"}


def is_zig_config(config):
    """Zig is used for all non-Windows targets and Windows out dirs containing 'zig'."""
    return (not config[3]) or ("zig" in config[1])


def effective_out_dir(out_dir):
    """Sanitizer builds never overwrite release binaries."""
    if SANITIZER_MODE:
        return out_dir + SANITIZER_SUFFIX[SANITIZER_MODE]
    return out_dir + BUILD_OUTPUT_SUFFIX


def check_zig():
    if not ZIG_EXE.exists():
        log(f"ERROR: Zig not found at {ZIG_EXE}")
        log("Please download Zig 0.15.2 and extract to toolchains/zig-x86_64-windows-0.15.2/")
        sys.exit(1)


def check_llvm_mingw():
    clang = LLVM_MINGW_BIN / "x86_64-w64-mingw32-clang++.exe"
    if not clang.exists():
        log(f"ERROR: LLVM MinGW not found at {LLVM_MINGW_DIR}")
        log("Please download llvm-mingw 20260519 (ucrt-x86_64) and extract to "
            "toolchains/llvm-mingw-20260519-ucrt-x86_64/")
        sys.exit(1)


def version_defines(out_dir="custom"):
    return [
        f'-DSHADERSTRESS_BUILD_LABEL="{Path(out_dir).name}"',
        f'-DAPP_VERSION_TEXT="{APP_VERSION_TEXT}"',
        f"-DAPP_VERSION_MAJOR_NUM={APP_VERSION_MAJOR}",
        f"-DAPP_VERSION_MINOR_NUM={APP_VERSION_MINOR}",
        f"-DAPP_VERSION_PATCH_NUM={APP_VERSION_PATCH}",
    ]


def common_cxx_flags(out_dir):
    """Flags shared by every C++ build of the main binary.

    -O3 with strict IEEE FP semantics (no -ffast-math): every result must be
    bit-reproducible across call sites and cores for the redundant job
    verification. Unwind tables are kept so crash dumps have usable stacks.
    Strict aliasing is ON (explicit -fstrict-aliasing): P007c measured +1.9 W on
    the realistic sim from TBAA alone. Type-punning through unrelated pointer
    types is therefore UB in this codebase — use memcpy or explicitly may_alias
    types.

    Defaults are the measured-best variant (promotion rule, user instruction
    2026-10-06): every accepted power setting lives in the default flag set,
    `scripts/build_kernels.py` or the `Workloads.h` knob defaults — never behind
    an opt-in variant. Comparison variants (`-nounroll`, `-strictalias-off`,
    `-znver3`, `-nolto`, `-slp`, `-interleave1`, `--sweep` `-tuning` builds) are
    single-setting A/B arms and get promoted into these defaults when they win
    (see llm-wiki/power-ledger.md). `tests/run_tests.py`'s
    `test_default_build_is_best_variant` pins this set.
    """
    flags = [
        "-std=c++20", "-O3",
        "-I", str(SRC_DIR),
        "-fno-math-errno",
        "-fno-rtti",
        "-fno-exceptions",
        "-fno-stack-protector",
        "-fomit-frame-pointer",
        "-fstrict-aliasing",
        "-ffunction-sections", "-fdata-sections",
        "-fno-ident",
        "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-missing-field-initializers",
    ]
    variant = out_dir.removesuffix(BUILD_OUTPUT_SUFFIX) if BUILD_OUTPUT_SUFFIX else out_dir
    for suffix in SANITIZER_SUFFIX.values():
        variant = variant.removesuffix(suffix)
    if not variant.endswith("-nounroll"):
        flags.append("-funroll-loops")
    if variant.endswith("-strictalias-off"):
        # Regression arm: restores the pre-P007c -fno-strict-aliasing default.
        flags.append("-fno-strict-aliasing")
    if variant.endswith("-znver3"):
        flags.append("-mtune=znver3")
    if variant.endswith("-simv5"):
        # Test build: scalar-sim runs the experimental V5 shader-compiler model
        # instead of the pinned V3 (a workload choice, not a power flag).
        flags.append("-DSHADERSTRESS_REALISTIC_V5")
    if variant.endswith("-interleave1"):
        # P028: vectorizer interleave 1 for the pinned realistic sim (LTO/main
        # objects only; native kernel objects keep build_kernels.py flags).
        flags += ["-mllvm", "-force-vector-interleave=1"]
    return flags


def release_lto(out_dir, macos=False):
    """LTO is an accepted power setting (P007b kept it on). Defaults are the
    measured-best variant: LTO is on for release builds except Apple targets
    and the `win-v3-nolto` single-setting A/B arm (promotion rule)."""
    return not macos and "-nolto" not in out_dir


def sanitizer_flags():
    if SANITIZER_MODE == "undefined":
        return ["-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-g", "-O1",
                "-fno-omit-frame-pointer"]
    if SANITIZER_MODE == "address":
        return ["-fsanitize=address", "-fsanitize-address-use-after-scope", "-g", "-O1",
                "-fno-omit-frame-pointer"]
    if SANITIZER_MODE == "thread":
        return ["-fsanitize=thread", "-g", "-O1"]
    return []


def pgo_flags(target):
    if PGO_MODE == "generate":
        return ["-fprofile-generate"]
    if PGO_MODE == "use":
        profdata = BASE_DIR / "default.profdata"
        if profdata.exists():
            return [f"-fprofile-use={profdata}"]
        log(f"WARNING: {profdata} not found, skipping PGO for {target}")
    return []


def collect_warnings(stderr_bytes):
    text = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    return [line for line in text.splitlines() if "warning:" in line]


def build_windows_resource(out_path):
    """Compile .rc resource file using llvm-windres"""
    res_file = out_path / "resource.res"
    rc_src = RESOURCE_RC
    if not rc_src.exists():
        log("Warning: resources/resource.rc not found, skipping resource compilation")
        return None
    windres = LLVM_MINGW_BIN / "llvm-windres.exe"
    try:
        subprocess.run([str(windres), str(rc_src), "-o", str(res_file)],
                       check=True, capture_output=True, cwd=rc_src.parent)
        return str(res_file)
    except subprocess.CalledProcessError as e:
        log(f"Warning: Could not compile resource.rc: {e}")
        return None


def set_pe_checksum(exe_path):
    """Compute and write the PE checksum using the standard algorithm."""
    try:
        data = bytearray(exe_path.read_bytes())
        if len(data) < 256:
            return False
        e_lfanew = int.from_bytes(data[60:64], "little")
        opt_magic = int.from_bytes(data[e_lfanew + 24:e_lfanew + 26], "little")
        if opt_magic == 0x20b:
            checksum_off = e_lfanew + 24 + 64
        elif opt_magic == 0x10b:
            checksum_off = e_lfanew + 24 + 68
        else:
            return False
        data[checksum_off:checksum_off + 4] = b'\x00\x00\x00\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = int.from_bytes(data[i:i + 2], "little")
            total = (total + word) & 0xFFFFFFFF
            total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        total = (total + len(data)) & 0xFFFFFFFF
        data[checksum_off:checksum_off + 4] = total.to_bytes(4, "little")
        exe_path.write_bytes(data)
        return True
    except Exception:
        return False


def build_windows_cli_launcher(target, cpu, out_path):
    """Build the tiny CLI launcher (.com) using LLVM MinGW"""
    launcher_path = out_path / "ShaderStress.com"
    arch = MINGW_ARCH_MAP.get(target, "x86_64")
    clang_exe = LLVM_MINGW_BIN / f"{arch}-w64-mingw32-clang.exe"
    cmd = [str(clang_exe), "-Oz", "-s", "-ffunction-sections", "-fdata-sections",
           "-fno-asynchronous-unwind-tables", "-fno-ident", "-municode"]
    march = CPU_ARCH_MAP.get(cpu)
    if march:
        cmd.append(f"-march={march}")
    cmd += [str(CLI_LAUNCHER_SOURCE), "-o", str(launcher_path),
            "-Wl,--subsystem,console", "-Wl,--gc-sections"]
    subprocess.run(cmd, check=True, capture_output=True, cwd=BASE_DIR)


def build_power_reader(out_path):
    """Compile PowerReader.cs (C# LHM helper) and copy the LHM runtime files."""
    lhm_src = BASE_DIR / "vendor" / "lhm"
    power_reader_cs = lhm_src / "PowerReader.cs"
    if not (power_reader_cs.exists() and lhm_src.exists()):
        return
    lhm_out = out_path / "lhm"
    lhm_out.mkdir(parents=True, exist_ok=True)
    csc = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / \
        "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"
    if csc.exists():
        lhm_dll = lhm_src / "LibreHardwareMonitorLib.dll"
        pr_exe = lhm_out / "PowerReader.exe"
        subprocess.run([
            str(csc), "/target:exe", f"/out:{pr_exe}",
            "/platform:x64", "/nologo",
            f"/reference:{lhm_dll}",
            str(power_reader_cs),
        ], check=True, capture_output=True)
        # .NET 4.8 app.config (needed for the Mutex ctor used by LHM)
        pr_exe.with_suffix(".exe.config").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<configuration>\n'
            '  <startup>\n'
            '    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />\n'
            '  </startup>\n'
            '</configuration>\n', encoding="utf-8")
    needed = LHM_DEPS_FILES + ["install-pawnio.ps1", "uninstall-pawnio.ps1"]
    for name in needed:
        src = lhm_src / name
        if src.exists() and not (lhm_out / name).exists():
            shutil.copy2(src, lhm_out / name)


def build_windows_target(config):
    """Build a Windows target using LLVM MinGW"""
    target, out_dir, cpu, is_windows, archive_name, _ = config
    out_dir = effective_out_dir(out_dir)
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    for stale_name in ["ShaderStress.com", "ShaderStressCli.exe", "ShaderStressGui.exe", "ShaderStressCli.cmd"]:
        stale_path = out_path / stale_name
        if stale_path.exists():
            stale_path.unlink()

    arch = MINGW_ARCH_MAP.get(target, "x86_64")
    clang_exe = LLVM_MINGW_BIN / f"{arch}-w64-mingw32-clang++.exe"
    log(f"Starting {target} (cpu={cpu}) -> {out_dir} using {clang_exe.name}...")

    defines = ["-DUNICODE", "-D_UNICODE", "-D_WIN32_WINNT=0x0A00", "-DDISABLE_SEH"]
    if "aarch64" in target:
        defines += ["-D_M_ARM64", "-D_WIN64"]
    defines += version_defines(out_dir) + EXTRA_DEFINES

    exe_path = out_path / "ShaderStress.exe"
    pdb_path = out_path / "ShaderStress.pdb"
    try:
        src_files = list(SRC_FILES_WINDOWS)
        res_file = build_windows_resource(out_path)
        if res_file:
            src_files.append(res_file)

        cmd = [str(clang_exe)]
        march = CPU_ARCH_MAP.get(cpu)
        if march:
            cmd.append(f"-march={march}")
        if cpu == "x86_64_v4":
            cmd.append("-mprefer-vector-width=512")
        cmd += common_cxx_flags(out_dir)
        if SANITIZER_MODE:
            cmd += sanitizer_flags()
        else:
            # Release: LTO, CodeView debug info into a separate PDB, stripped exe.
            cmd += ["-g", "-gcodeview", "-s"]
            if release_lto(out_dir):
                cmd.append("-flto")
        cmd += pgo_flags(target)
        cmd += ["-static-libstdc++", "-static",
                "-Wno-macro-redefined", "-Wno-ignored-optimization-argument",
                "-Wno-ignored-attributes", "-Wno-writable-strings", "-municode"]
        cmd += defines
        src_files, kernel_warnings = build_kernels.compile_kernels(
            cmd, src_files, out_path, BASE_DIR, slp="-slp" in out_dir)
        cmd += src_files
        # Sanitizer builds use the console subsystem so the runtime's reports
        # reach stderr (a GUI-subsystem process has no std handles at startup).
        subsystem = "console" if SANITIZER_MODE else "windows"
        cmd += ["-o", str(exe_path),
                f"-Wl,--subsystem,{subsystem}", "-Wl,--gc-sections",
                "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", "-lshell32",
                "-lole32", "-loleaut32", "-ldbghelp", "-lwinmm"]
        if not SANITIZER_MODE:
            cmd.append(f"-Wl,--pdb={pdb_path}")
            if cpu in GUARDED_CPUS:
                cmd.append(f"-Wl,--entry,{GUARD_ENTRY}")
        proc = subprocess.run(cmd, check=True, capture_output=True, cwd=BASE_DIR)
        warnings = kernel_warnings + collect_warnings(proc.stderr)

        if SANITIZER_MODE == "address":
            # The ASan runtime is a DLL that itself links libc++/libunwind.
            triple_bin = LLVM_MINGW_DIR / f"{arch}-w64-mingw32" / "bin"
            for dll in ["libclang_rt.asan_dynamic-x86_64.dll", "libc++.dll", "libunwind.dll"]:
                for src in (LLVM_MINGW_BIN / dll, triple_bin / dll):
                    if src.exists():
                        shutil.copy2(src, out_path / dll)
                        break
        if not set_pe_checksum(exe_path):
            log(f"Warning: could not set PE checksum for {exe_path.name}")
        build_windows_cli_launcher(target, cpu, out_path)
        build_power_reader(out_path)
        return (True, target, out_dir, archive_name, warnings)
    except subprocess.CalledProcessError as e:
        return (False, target, out_dir, failure_message(e), [])


def failure_message(e):
    msg = f"Exit {e.returncode}"
    if e.stderr:
        text = e.stderr.decode("utf-8", errors="ignore")
        errors = [line for line in text.splitlines() if "error" in line.lower()]
        msg += ": " + ("\n".join(errors[:15]) if errors else text[-1500:])
    return msg


def build_zig_target(config):
    """Build a target using Zig (Linux/macOS/Windows)."""
    target, out_dir, cpu, is_windows, archive_name, _ = config
    out_dir = effective_out_dir(out_dir)
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    log(f"Starting {target} (cpu={cpu}) -> {out_dir} using Zig...")

    if is_windows:
        for stale_name in ["ShaderStress.com", "ShaderStressCli.exe", "ShaderStressGui.exe", "ShaderStressCli.cmd"]:
            stale_path = out_path / stale_name
            if stale_path.exists():
                stale_path.unlink()

    src_files = list(SRC_FILES_WINDOWS if is_windows else SRC_FILES_UNIX)
    if is_windows:
        defines = ["-DUNICODE", "-D_UNICODE", "-D_WIN32_WINNT=0x0A00"]
        if "aarch64" in target:
            defines += ["-D_M_ARM64", "-D_WIN64"]
    else:
        defines = ["-DPLATFORM_LINUX" if "linux" in target else "-DPLATFORM_MACOS"]
    defines += version_defines(out_dir) + ["-DDISABLE_SEH"] + EXTRA_DEFINES

    exe_path = out_path / ("ShaderStress.exe" if is_windows else "shaderstress")
    is_macos = "macos" in target
    try:
        cmd = [str(ZIG_EXE), "c++", "-target", target]
        if cpu != "generic":
            cmd.append("-mcpu=" + cpu)
        if cpu == "x86_64_v4":
            cmd.append("-mprefer-vector-width=512")
        cmd += common_cxx_flags(out_dir)
        if "linux" in target:
            cmd.append("-fno-semantic-interposition")
        if SANITIZER_MODE:
            cmd += sanitizer_flags()
        else:
            if release_lto(out_dir, macos=is_macos):
                cmd.append("-flto")
            # Windows: Zig emits a PDB next to the exe. Linux: DWARF is split
            # into shaderstress.debug below. macOS: stripped (no dsymutil).
            cmd += ["-g"] if not is_macos else ["-s"]
        cmd += pgo_flags(target)
        cmd += ["-Wno-macro-redefined", "-Wno-ignored-optimization-argument"]
        if is_windows:
            cmd.append("-municode")
        cmd += defines

        if is_windows:
            res_file = out_path / "resource.res"
            try:
                subprocess.run([str(ZIG_EXE), "rc", str(RESOURCE_RC), str(res_file)],
                               check=True, capture_output=True, cwd=RESOURCE_RC.parent)
                src_files.append(str(res_file))
            except subprocess.CalledProcessError as e:
                log(f"Warning: Could not compile resource.rc for {target}: {e}")

        src_files, kernel_warnings = build_kernels.compile_kernels(
            cmd, src_files, out_path, BASE_DIR)
        cmd += src_files
        if is_windows:
            cmd += ["-o", str(exe_path),
                    "-Xlinker", "--subsystem", "-Xlinker", "windows",
                    "-Xlinker", "--gc-sections",
                    "-luser32", "-lgdi32", "-ldwmapi", "-lshcore",
                    "-lshell32", "-lole32", "-loleaut32", "-ldbghelp", "-lwinmm"]
            if cpu in GUARDED_CPUS and not SANITIZER_MODE:
                cmd += ["-Xlinker", "--entry", "-Xlinker", GUARD_ENTRY]
        else:
            cmd += ["-o", str(exe_path), "-lpthread"]
            if not is_macos:
                cmd += ["-Wl,--sort-common,--sort-section=alignment", "-Wl,--gc-sections"]
        proc = subprocess.run(cmd, check=True, capture_output=True, cwd=BASE_DIR)
        warnings = kernel_warnings + collect_warnings(proc.stderr)

        if "linux" in target and not SANITIZER_MODE and LLVM_OBJCOPY.exists():
            debug_path = out_path / "shaderstress.debug"
            subprocess.run([str(LLVM_OBJCOPY), "--only-keep-debug", str(exe_path), str(debug_path)],
                           check=True, capture_output=True)
            subprocess.run([str(LLVM_OBJCOPY), "--strip-debug", "--strip-unneeded",
                            f"--add-gnu-debuglink={debug_path}", str(exe_path)],
                           check=True, capture_output=True)

        if is_windows:
            launcher_path = out_path / "ShaderStress.com"
            zig_cc_cmd = [str(ZIG_EXE), "cc", "-target", target]
            if cpu != "generic":
                zig_cc_cmd.append("-mcpu=" + cpu)
            zig_cc_cmd += ["-Oz", "-s", "-ffunction-sections", "-fdata-sections",
                           "-fno-asynchronous-unwind-tables", "-fno-ident", "-municode",
                           str(CLI_LAUNCHER_SOURCE), "-o", str(launcher_path),
                           "-Xlinker", "--subsystem", "-Xlinker", "console",
                           "-Xlinker", "--gc-sections"]
            subprocess.run(zig_cc_cmd, check=True, capture_output=True, cwd=BASE_DIR)
            build_power_reader(out_path)
        return (True, target, out_dir, archive_name, warnings)
    except subprocess.CalledProcessError as e:
        return (False, target, out_dir, failure_message(e), [])


def fetch_lhm_deps():
    """Download LHM dependency files from GitHub if not present locally.
    Aborts the build if SHA256 hashes or digital signatures are invalid."""
    lhm_dir = BASE_DIR / "vendor" / "lhm"
    sha_file = lhm_dir / "SHA256SUMS.txt"
    if sha_file.exists():
        hashes = parse_sha_list(sha_file.read_text(encoding="utf-8"))
        all_ok = all(
            (lhm_dir / f).exists() and file_sha256(lhm_dir / f) == h
            for f, h in hashes.items() if f in LHM_DEPS_FILES
        )
        if all_ok:
            verify_signatures(lhm_dir)
            return

    log("Fetching LHM dependencies from GitHub...")
    lhm_dir.mkdir(parents=True, exist_ok=True)
    sha_content = download_file(f"{LHM_DEPS_URL}/SHA256SUMS.txt")
    if not sha_content:
        fail("Could not download SHA256SUMS.txt from GitHub")
    (lhm_dir / "SHA256SUMS.txt").write_bytes(sha_content)
    hashes = parse_sha_list(sha_content.decode("utf-8"))
    for name in LHM_DEPS_FILES:
        dest = lhm_dir / name
        expected = hashes.get(name)
        if not expected:
            fail(f"No hash for {name} in SHA256SUMS.txt")
        if dest.exists() and file_sha256(dest) == expected:
            continue
        url = f"{LHM_DEPS_URL}/{name}"
        data = download_file(url)
        if not data:
            fail(f"Could not download {name} from {url}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            fail(f"SHA256 mismatch for {name}: expected {expected}, got {actual}")
        dest.write_bytes(data)
        log(f"  Downloaded {name} (hash OK)")
    verify_signatures(lhm_dir)


def parse_sha_list(text):
    hashes = {}
    for line in text.splitlines():
        parts = line.strip().split("  ", 1)
        if len(parts) == 2:
            hashes[parts[1]] = parts[0]
    return hashes


def verify_signatures(lhm_dir):
    """Verify Authenticode signatures on .dll and .exe files. Windows only."""
    if sys.platform != "win32":
        return
    signable = [f for f in LHM_DEPS_FILES
                if f.endswith((".dll", ".exe")) and (lhm_dir / f).exists()]
    if not signable:
        return
    file_list = ",".join(f"'{lhm_dir / f}'" for f in signable)
    ps = (
        f"foreach($f in @({file_list})){{"
        f"$s=Get-AuthenticodeSignature $f;"
        f"$name=Split-Path $f -Leaf;"
        f"Write-Output ($s.Status.ToString()+':'+$name)"
        f"}}"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=30, encoding="utf-8", errors="replace"
        )
        for line in result.stdout.strip().splitlines():
            if ":" not in line:
                continue
            status, name = (part.strip() for part in line.split(":", 1))
            if status == "Valid":
                log(f"  Signed: {name}")
            elif status == "NotSigned" and name.endswith(".dll"):
                log(f"  Unsigned (OK): {name}")
            else:
                fail(f"Signature invalid for {name}: {status}")
    except Exception as e:
        log(f"WARNING: Could not verify signatures: {e}")


def download_file(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "shaderstress-build"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception:
        return None


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    log(f"ERROR: {msg}")
    sys.exit(1)


def build_target(config):
    """Build a single target – dispatch to the right toolchain"""
    if config[0].endswith("-msvc"):
        return build_msvc.build(config, sys.modules[__name__])
    if is_zig_config(config):
        return build_zig_target(config)
    return build_windows_target(config)


def create_archives(results):
    """Create distribution archives in parallel (release builds only)"""
    log("Creating distribution archives...")
    dist_dir = BASE_DIR / "dist"
    dist_dir.mkdir(exist_ok=True)
    sevenzip = None
    for path in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]:
        if os.path.exists(path):
            sevenzip = path
            break

    def create_archive(result):
        success, target, out_dir, archive_name, _ = result
        if not success or not archive_name:
            return False
        archive_path = dist_dir / archive_name
        src_dir = BASE_DIR / out_dir
        files = ["ShaderStress.exe", "ShaderStress.com"] if "windows" in target else ["shaderstress"]
        src_files = [src_dir / f for f in files]
        if not all(f.exists() for f in src_files):
            return False
        try:
            if archive_path.exists():
                archive_path.unlink()
            if sevenzip:
                subprocess.run([sevenzip, "a", "-mx=9", str(archive_path)] + [str(f) for f in src_files],
                               check=True, capture_output=True)
            else:
                import zipfile
                with zipfile.ZipFile(archive_path.with_suffix(".zip"), 'w', zipfile.ZIP_DEFLATED,
                                     compresslevel=9) as zf:
                    for f in src_files:
                        zf.write(f, f.name)
            return True
        except Exception as e:
            log(f"Failed to create {archive_name}: {e}")
            return False

    with ThreadPoolExecutor(max_workers=4) as executor:
        archive_results = list(executor.map(create_archive, results))
    log(f"Created {sum(archive_results)} archives")
    write_checksums(dist_dir)


def write_checksums(dist_dir):
    entries = []
    for archive in sorted(dist_dir.iterdir()):
        if not archive.is_file() or archive.name == "SHA256SUMS.txt":
            continue
        entries.append(f"{file_sha256(archive)}  {archive.name}")
    (dist_dir / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")
    log("Wrote checksums to SHA256SUMS.txt")


def main():
    global PGO_MODE, SANITIZER_MODE, BUILD_OUTPUT_SUFFIX
    log(f"Version: {APP_VERSION_TEXT}")
    targets_requested = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    for flag, mode in (("--pgo-gen", "generate"), ("--pgo-use", "use")):
        if flag in targets_requested:
            PGO_MODE = mode
            targets_requested.remove(flag)
    for flag, mode in (("--sanitize", "undefined"), ("--sanitize=undefined", "undefined"),
                       ("--sanitize=address", "address"), ("--sanitize=thread", "thread")):
        if flag in targets_requested:
            SANITIZER_MODE = mode
            targets_requested.remove(flag)
    if not targets_requested:
        targets_requested = ["all"]
    if any(t in ("help", "-h", "--help") for t in targets_requested):
        print_help()
        return 0

    if EXTRA_DEFINES:
        BUILD_OUTPUT_SUFFIX = "-tuning"
        log("Tuning defines active: using isolated -tuning output dirs; no release archives")
    configs = select_configs(targets_requested)
    if any(c[0].endswith("-msvc") for c in configs):
        if build_msvc.discover(BASE_DIR) is None or SANITIZER_MODE or PGO_MODE:
            if any(t in ("msvc", "msvc-v3", "x64-msvc-v3") for t in targets_requested):
                fail("MSVC x64 not available, or incompatible sanitizer/PGO option selected")
            log("Skipping optional MSVC (unavailable or Clang sanitizer/PGO build)")
            configs = [c for c in configs if not c[0].endswith("-msvc")]
        else:
            log("Native MSVC x64 detected; including MSVC comparison build")
    if not configs:
        log("No targets to build")
        return 1
    if SANITIZER_MODE:
        log(f"Sanitizer build: {SANITIZER_MODE} (output dirs get suffix "
            f"{SANITIZER_SUFFIX[SANITIZER_MODE]})")

    if any(c[3] and not is_zig_config(c) and not c[0].endswith("-msvc") for c in configs):
        check_llvm_mingw()
    if any(c[3] for c in configs):
        fetch_lhm_deps()
    if any(is_zig_config(c) for c in configs):
        check_zig()

    max_workers = min(len(configs), multiprocessing.cpu_count())
    log(f"Building {len(configs)} targets with {max_workers} parallel jobs...")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(build_target, c): c for c in configs}
        for future in as_completed(future_to_config):
            config = future_to_config[future]
            try:
                result = future.result()
            except Exception as e:
                result = (False, config[0], config[1], str(e), [])
            results.append(result)
            success, target, out_dir, msg, _ = result
            log(f"OK {target} -> {out_dir}" if success else f"FAIL {target} -> {out_dir}: {msg}")

    warnings = sorted({w for r in results for w in r[4]})
    if warnings:
        log(f"{len(warnings)} unique compiler warning(s):")
        for w in warnings[:40]:
            print("  " + w)
    successful = sum(1 for r in results if r[0])
    log(f"Build complete: {successful}/{len(results)} targets succeeded")
    if not SANITIZER_MODE and PGO_MODE is None and not EXTRA_DEFINES:
        create_archives(results)
    return 0 if successful == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
