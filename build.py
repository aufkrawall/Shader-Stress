#!/usr/bin/env python3
"""
ShaderStress Build Script
Windows: LLVM MinGW (clang++ / lld)
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

# Configuration
BASE_DIR = Path.cwd()
ZIG_DIR = BASE_DIR / "zig-x86_64-windows-0.15.2"
ZIG_EXE = ZIG_DIR / "zig.exe"
LLVM_MINGW_DIR = BASE_DIR / "llvm-mingw-20260519-ucrt-x86_64" / "llvm-mingw-20260519-ucrt-x86_64"
LLVM_MINGW_BIN = LLVM_MINGW_DIR / "bin"
VERSION_FILE = BASE_DIR / "VERSION"
CLI_LAUNCHER_SOURCE = BASE_DIR / "cli_launcher.c"


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


# Source files
SRC_FILES_WINDOWS = [
    "Common.cpp", "CpuFeatures.cpp", "Platform.cpp",
    "Workloads.cpp", "Threading.cpp", "Gui.cpp", "ShaderStress.cpp"
]
SRC_FILES_UNIX = [
    "Common.cpp", "CpuFeatures.cpp", "Platform.cpp",
    "Workloads.cpp", "Threading.cpp", "TerminalUtils.cpp", "ShaderStress.cpp"
]

# Build configurations
# (target, out_dir, cpu, is_windows, archive_name)
BUILD_CONFIGS = [
    # Windows (LLVM MinGW)
    ("x86_64-windows-gnu", "bin/x64-llvm", "x86_64", True, "ShaderStress-Windows-x64.7z"),
    ("x86_64-windows-gnu", "bin/x64-llvm-v3", "x86_64_v3", True, "ShaderStress-Windows-x64-v3.7z"),
    ("x86_64-windows-gnu", "bin/x64-llvm-v4", "x86_64_v4", True, "ShaderStress-Windows-x64-v4.7z"),
    ("aarch64-windows-gnu", "bin/arm64-llvm", "generic", True, "ShaderStress-Windows-ARM64.7z"),
    # Linux (Zig)
    ("x86_64-linux-gnu", "bin/linux-x64", "x86_64", False, "ShaderStress-Linux-x64.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64-v3", "x86_64_v3", False, "ShaderStress-Linux-x64-v3.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64-v4", "x86_64_v4", False, "ShaderStress-Linux-x64-v4.7z"),
    ("aarch64-linux-gnu", "bin/linux-arm64", "generic", False, "ShaderStress-Linux-ARM64.7z"),
    ("x86_64-macos", "bin/macos-x64", "x86_64", False, "ShaderStress-macOS-x64.7z"),
    ("aarch64-macos", "bin/macos-arm64", "generic", False, "ShaderStress-macOS-ARM64.7z"),
]

# Map Zig-style CPU levels to Clang -march flags (Windows/LLVM MinGW only)
CPU_ARCH_MAP = {
    "x86_64": None,        # baseline is default for x86_64-w64-windows-gnu
    "x86_64_v3": "x86-64-v3",
    "x86_64_v4": "x86-64-v4",
    "generic": None,
}

# Map target triples to LLVM MinGW toolchain prefix
MINGW_ARCH_MAP = {
    "x86_64-windows-gnu": "x86_64",
    "aarch64-windows-gnu": "aarch64",
}


def log(msg):
    print(f"[BUILD] {msg}", flush=True)


APP_VERSION_TEXT, APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH = load_version()


def check_zig():
    """Verify Zig is available (needed for Linux/macOS builds)"""
    if not ZIG_EXE.exists():
        log(f"ERROR: Zig not found at {ZIG_EXE}")
        log("Please download Zig 0.15.2 and extract to zig-x86_64-windows-0.15.2/")
        sys.exit(1)


def check_llvm_mingw():
    """Verify LLVM MinGW toolchain is available (needed for Windows builds)"""
    clang = LLVM_MINGW_BIN / "x86_64-w64-mingw32-clang++.exe"
    if not clang.exists():
        log(f"ERROR: LLVM MinGW not found at {LLVM_MINGW_DIR}")
        log("Please download llvm-mingw and extract to llvm-mingw-*/")
        sys.exit(1)


def build_windows_resource(out_path):
    """Compile .rc resource file using llvm-windres"""
    res_file = out_path / "resource.res"
    rc_src = BASE_DIR / "resource.rc"
    if not rc_src.exists():
        log("Warning: resource.rc not found, skipping resource compilation")
        return None

    windres = LLVM_MINGW_BIN / "llvm-windres.exe"
    try:
        subprocess.run([str(windres), str(rc_src), "-o", str(res_file)],
                       check=True, capture_output=True)
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
        # Locate PE checksum field: offset in optional header differs for PE32/PE32+
        dos = data[:64]
        e_lfanew = int.from_bytes(dos[60:64], "little")
        nt_offset = e_lfanew + 4  # skip PE\0\0 signature
        fh = data[nt_offset:nt_offset + 20]
        opt_magic = int.from_bytes(data[e_lfanew + 24:e_lfanew + 26], "little")
        # PE32+: Checksum at optional header offset 64
        # PE32: Checksum at optional header offset 68
        if opt_magic == 0x20b:
            checksum_off = e_lfanew + 24 + 64
        elif opt_magic == 0x10b:
            checksum_off = e_lfanew + 24 + 68
        else:
            return False
        # Zero out the checksum field for calculation
        data[checksum_off:checksum_off + 4] = b'\x00\x00\x00\x00'
        # Compute one's complement sum over all WORDs, then add file size
        total = 0
        for i in range(0, len(data), 2):
            word = int.from_bytes(data[i:i + 2], "little")
            total = (total + word) & 0xFFFFFFFF
        total = (total + len(data)) & 0xFFFFFFFF
        # Write checksum
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

    cmd = [
        str(clang_exe),
        "-Oz", "-s",
        "-ffunction-sections", "-fdata-sections",
        "-fno-asynchronous-unwind-tables",
        "-fno-ident",
        "-municode",
    ]

    # Map CPU level for the launcher
    march = CPU_ARCH_MAP.get(cpu)
    if march:
        cmd.append(f"-march={march}")

    cmd.extend([
        str(CLI_LAUNCHER_SOURCE),
        "-o", str(launcher_path),
        "-Wl,--subsystem,console",
        "-Wl,--gc-sections",
    ])
    subprocess.run(cmd, check=True, capture_output=True)


# PGO mode: None, "generate", or "use"
PGO_MODE = None
# Sanitizer mode: None, "undefined", "address", or "thread"
SANITIZER_MODE = None


def build_windows_target(config):
    """Build a Windows target using LLVM MinGW"""
    target, out_dir, cpu, is_windows, archive_name = config
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)

    # Clean stale outputs
    for stale_name in ["ShaderStress.com", "ShaderStressCli.exe", "ShaderStressGui.exe", "ShaderStressCli.cmd"]:
        stale_path = out_path / stale_name
        if stale_path.exists():
            stale_path.unlink()

    arch = MINGW_ARCH_MAP.get(target, "x86_64")
    clang_exe = LLVM_MINGW_BIN / f"{arch}-w64-mingw32-clang++.exe"

    log(f"Starting {target} (cpu={cpu}) using {clang_exe.name}...")

    src_files = SRC_FILES_WINDOWS[:]
    defines = ["-DUNICODE", "-D_UNICODE", "-D_WIN32_WINNT=0x0A00"]

    if "arm64" in target:
        defines.extend(["-D_M_ARM64", "-D_WIN64"])

    defines.extend([
        f'-DAPP_VERSION_TEXT="{APP_VERSION_TEXT}"',
        f"-DAPP_VERSION_MAJOR_NUM={APP_VERSION_MAJOR}",
        f"-DAPP_VERSION_MINOR_NUM={APP_VERSION_MINOR}",
        f"-DAPP_VERSION_PATCH_NUM={APP_VERSION_PATCH}",
    ])

    defines.append("-DDISABLE_SEH")

    exe_name = "ShaderStress.exe"
    exe_path = out_path / exe_name

    try:
        # Compile resource file
        res_file = build_windows_resource(out_path)
        if res_file:
            src_files.append(res_file)

        # Base compiler flags
        base_cmd = [str(clang_exe)]

        # CPU architecture selection
        march = CPU_ARCH_MAP.get(cpu)
        if march:
            base_cmd.append(f"-march={march}")

        # Force 512-bit ZMM vector width on x86_64_v4 targets
        if cpu == "x86_64_v4":
            base_cmd.append("-mprefer-vector-width=512")

        base_cmd.extend([
            "-std=c++20", "-O3",
            "-ffast-math",
            "-fno-rtti",
            "-fno-exceptions",
            "-fno-stack-protector",
            "-fomit-frame-pointer",
            "-ffunction-sections", "-fdata-sections",
            "-fno-asynchronous-unwind-tables",
            "-fno-ident",
        ])

        # Sanitizer build mode (development only)
        if SANITIZER_MODE == "undefined":
            base_cmd.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
        elif SANITIZER_MODE == "address":
            base_cmd.extend(["-fsanitize=address", "-fno-omit-frame-pointer", "-fsanitize-address-use-after-scope"])
        elif SANITIZER_MODE == "thread":
            base_cmd.append("-fsanitize=thread")

        # LTO is supported on Windows/LLVM MinGW
        if SANITIZER_MODE is None:
            base_cmd.append("-flto")

        # PGO support
        if PGO_MODE == "generate":
            base_cmd.append("-fprofile-generate")
        elif PGO_MODE == "use":
            profdata = BASE_DIR / "default.profdata"
            if profdata.exists():
                base_cmd.append(f"-fprofile-use={profdata}")
            else:
                log(f"WARNING: {profdata} not found, skipping PGO for {target}")

        base_cmd.extend([
            "-s",
            "-static-libstdc++",
            "-static",
            "-Wno-macro-redefined",
            "-Wno-ignored-optimization-argument",
            "-Wno-ignored-attributes",
            "-Wno-writable-strings",
            "-municode",
        ])

        # NOTE: -fcf-protection=full removed (extra branch checks reduce power draw)

        base_cmd.extend(defines)
        base_cmd.extend(src_files)

        # Linker flags
        cmd = base_cmd[:] + [
            "-o", str(exe_path),
            "-Wl,--subsystem,windows",
            "-Wl,--gc-sections",
        "-luser32", "-lgdi32", "-ldwmapi", "-lshcore",
        "-lshell32", "-lole32", "-loleaut32", "-lwbemuuid", "-ldbghelp",
        ]

        cmd = [c for c in cmd if c]
        subprocess.run(cmd, check=True, capture_output=True)

        # Set PE checksum for image integrity validation
        if set_pe_checksum(exe_path):
            log(f"PE checksum set for {exe_path.name}")
        else:
            log(f"Warning: could not set PE checksum for {exe_path.name}")

        # Build the CLI launcher
        build_windows_cli_launcher(target, cpu, out_path)

        return (True, target, out_dir, archive_name)

    except subprocess.CalledProcessError as e:
        error_msg = f"Exit {e.returncode}"
        if e.stderr:
            try:
                error_msg += f": {e.stderr.decode('utf-8', errors='ignore')[:200]}"
            except:
                pass
        return (False, target, out_dir, error_msg)


def build_zig_target(config):
    """Build a Linux/macOS target using Zig"""
    target, out_dir, cpu, is_windows, archive_name = config
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)

    log(f"Starting {target} (cpu={cpu}) using Zig...")

    src_files = SRC_FILES_UNIX[:]
    defines = ["-DPLATFORM_LINUX" if "linux" in target else "-DPLATFORM_MACOS"]

    defines.extend([
        f'-DAPP_VERSION_TEXT="{APP_VERSION_TEXT}"',
        f"-DAPP_VERSION_MAJOR_NUM={APP_VERSION_MAJOR}",
        f"-DAPP_VERSION_MINOR_NUM={APP_VERSION_MINOR}",
        f"-DAPP_VERSION_PATCH_NUM={APP_VERSION_PATCH}",
    ])

    defines.append("-DDISABLE_SEH")

    exe_name = "shaderstress"
    exe_path = out_path / exe_name

    try:
        # Main build command
        use_lto = "macos" not in target

        base_cmd = [
            str(ZIG_EXE), "c++",
            "-target", target,
        ]

        if cpu != "generic":
            base_cmd.extend(["-mcpu=" + cpu])

        if cpu == "x86_64_v4":
            base_cmd.append("-mprefer-vector-width=512")

        base_cmd.extend([
            "-std=c++20", "-O3",
            "-ffast-math",
            "-fno-rtti",
            "-fno-exceptions",
            "-fno-semantic-interposition",
            "-fno-stack-protector",
            "-fomit-frame-pointer",
            "-ffunction-sections", "-fdata-sections",
            "-fno-asynchronous-unwind-tables",
            "-fno-ident",
        ])

        # Sanitizer build mode (development only)
        if SANITIZER_MODE == "undefined":
            base_cmd.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
        elif SANITIZER_MODE == "address":
            base_cmd.extend(["-fsanitize=address", "-fno-omit-frame-pointer"])
        elif SANITIZER_MODE == "thread":
            base_cmd.append("-fsanitize=thread")

        if use_lto and SANITIZER_MODE is None:
            base_cmd.append("-flto")

        if PGO_MODE == "generate":
            base_cmd.append("-fprofile-generate")
        elif PGO_MODE == "use":
            profdata = BASE_DIR / "default.profdata"
            if profdata.exists():
                base_cmd.append(f"-fprofile-use={profdata}")
            else:
                log(f"WARNING: {profdata} not found, skipping PGO for {target}")

        base_cmd.extend([
            "-s",
            "-Wno-macro-redefined",
            "-Wno-ignored-optimization-argument",
        ])

        base_cmd.extend(defines)
        base_cmd.extend(src_files)

        cmd = base_cmd[:] + [
            "-o", str(exe_path),
            "-lpthread",
            "-Wl,--sort-common,--sort-section=alignment",
            "-Wl,--gc-sections",
        ]

        cmd = [c for c in cmd if c]
        subprocess.run(cmd, check=True, capture_output=True)

        return (True, target, out_dir, archive_name)

    except subprocess.CalledProcessError as e:
        error_msg = f"Exit {e.returncode}"
        if e.stderr:
            try:
                error_msg += f": {e.stderr.decode('utf-8', errors='ignore')[:200]}"
            except:
                pass
        return (False, target, out_dir, error_msg)


def build_target(config):
    """Build a single target – dispatch to the right toolchain"""
    _, _, _, is_windows, _ = config
    if is_windows:
        return build_windows_target(config)
    else:
        return build_zig_target(config)


def create_archives(results):
    """Create distribution archives in parallel"""
    log("Creating distribution archives...")

    dist_dir = BASE_DIR / "dist"
    dist_dir.mkdir(exist_ok=True)

    # Find 7z
    sevenzip = None
    for path in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]:
        if os.path.exists(path):
            sevenzip = path
            break

    def create_archive(result):
        success, target, out_dir, archive_name = result
        if not success:
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
                cmd = [sevenzip, "a", "-mx=9", str(archive_path)] + [str(f) for f in src_files]
                subprocess.run(cmd, check=True, capture_output=True)
            else:
                import zipfile
                zip_path = archive_path.with_suffix(".zip")
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                    for f in src_files:
                        zf.write(f, f.name)

            return True
        except Exception as e:
            log(f"Failed to create {archive_name}: {e}")
            return False

    with ThreadPoolExecutor(max_workers=4) as executor:
        archive_results = list(executor.map(create_archive, results))

    successful = sum(archive_results)
    log(f"Created {successful}/{len(archive_results)} archives")
    write_checksums(dist_dir)


def write_checksums(dist_dir):
    """Write SHA256 checksums for all release archives"""
    checksum_entries = []

    for archive in sorted(dist_dir.iterdir()):
        if not archive.is_file() or archive.name == "SHA256SUMS.txt":
            continue
        hasher = hashlib.sha256()
        with archive.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        checksum_entries.append(f"{hasher.hexdigest()}  {archive.name}")

    checksums_path = dist_dir / "SHA256SUMS.txt"
    checksums_path.write_text("\n".join(checksum_entries) + "\n", encoding="utf-8")
    log(f"Wrote checksums to {checksums_path.name}")


def main():
    global PGO_MODE
    log(f"Version: {APP_VERSION_TEXT}")

    # Parse arguments
    targets_requested = sys.argv[1:] if len(sys.argv) > 1 else ["all"]

    # Extract PGO and sanitizer flags before other parsing
    if "--pgo-gen" in targets_requested:
        PGO_MODE = "generate"
        targets_requested.remove("--pgo-gen")
    if "--pgo-use" in targets_requested:
        PGO_MODE = "use"
        targets_requested.remove("--pgo-use")
    if "--sanitize" in targets_requested:
        SANITIZER_MODE = "undefined"
        targets_requested.remove("--sanitize")
    if "--sanitize=address" in targets_requested:
        SANITIZER_MODE = "address"
        targets_requested.remove("--sanitize=address")
    if "--sanitize=thread" in targets_requested:
        SANITIZER_MODE = "thread"
        targets_requested.remove("--sanitize=thread")

    if "help" in targets_requested or "-h" in targets_requested or "--help" in targets_requested:
        print("Usage: python build.py [targets...] [options]")
        print("Targets:")
        print("  all       - All platforms (default)")
        print("  windows   - Windows x64 and ARM64")
        print("  linux     - Linux x64 and ARM64")
        print("  macos     - macOS x64 and ARM64")
        print("  v4        - x86_64_v4 targets (AVX-512) only")
        print("  v3        - x86_64_v3 targets (AVX2+FMA) only")
        print("  native    - Current platform only")
        print("Options:")
        print("  --pgo-gen      Build with profile generation instrumentation")
        print("  --pgo-use      Build with profile-guided optimization (needs default.profdata)")
        print("  --sanitize     Build with UndefinedBehaviorSanitizer (development only)")
        print("  --sanitize=address  Build with AddressSanitizer (development only)")
        print("  --sanitize=thread   Build with ThreadSanitizer (development only)")
        print("")
        print("PGO workflow:")
        print("  1. python build.py --pgo-gen native")
        print("  2. ./bin/<target>/shaderstress --repro 42 10000 --quiet")
        print("  3. llvm-profdata merge -output=default.profdata *.profraw")
        print("  4. python build.py --pgo-use native")
        print("")
        print("Toolchains:")
        print("  Windows: LLVM MinGW (clang++/lld) - llvm-mingw-*/")
        print("  Linux/macOS: Zig cross-compilation - zig-x86_64-windows-0.15.2/zig.exe")
        print("")
        print("Examples:")
        print("  python build.py")
        print("  python build.py windows linux")
        return

    # Filter configs based on requested targets
    if "all" in targets_requested:
        configs = BUILD_CONFIGS
    else:
        configs = []
        for t in targets_requested:
            if t == "windows":
                configs.extend([c for c in BUILD_CONFIGS if "windows" in c[0]])
            elif t == "linux":
                configs.extend([c for c in BUILD_CONFIGS if "linux" in c[0]])
            elif t == "macos":
                configs.extend([c for c in BUILD_CONFIGS if "macos" in c[0]])
            elif t == "v4":
                configs.extend([c for c in BUILD_CONFIGS if "v4" in c[1]])
            elif t == "v3":
                configs.extend([c for c in BUILD_CONFIGS if "v3" in c[1]])
            elif t == "native":
                import platform
                machine = platform.machine().lower()
                system = platform.system().lower()
                if system == "windows":
                    candidates = [c for c in BUILD_CONFIGS if "windows" in c[0] and "x86_64" in c[0]]
                    for pref in ["v4", "v3", "llvm"]:
                        match = [c for c in candidates if pref in c[1]]
                        if match:
                            configs.append(match[0])
                            break
                elif system == "linux":
                    candidates = [c for c in BUILD_CONFIGS if "linux" in c[0] and "x86_64" in c[0]]
                    for pref in ["v4", "v3", "x64"]:
                        match = [c for c in candidates if pref in c[1]]
                        if match:
                            configs.append(match[0])
                            break
                elif system == "darwin":
                    if "arm" in machine:
                        configs.append([c for c in BUILD_CONFIGS if "macos" in c[0] and "aarch64" in c[0]][0])
                    else:
                        configs.append([c for c in BUILD_CONFIGS if "macos" in c[0] and "x86_64" in c[0]][0])

    if not configs:
        log("No targets to build")
        return

    # Remove duplicates while preserving order
    seen = set()
    unique_configs = []
    for c in configs:
        key = c[1]  # out_dir
        if key not in seen:
            seen.add(key)
            unique_configs.append(c)
    configs = unique_configs

    # Check toolchain availability
    has_windows = any(c[3] for c in configs)
    has_unix = any(not c[3] for c in configs)

    if has_windows:
        check_llvm_mingw()
    if has_unix:
        check_zig()

    log(f"Building {len(configs)} targets with {min(len(configs), multiprocessing.cpu_count())} parallel jobs...")

    # Build all targets in parallel
    results = []
    max_workers = min(len(configs), multiprocessing.cpu_count())

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {executor.submit(build_target, config): config for config in configs}

        for future in as_completed(future_to_config):
            config = future_to_config[future]
            try:
                result = future.result()
                results.append(result)
                success, target, out_dir, msg = result
                if success:
                    log(f"OK {target} -> {out_dir}")
                else:
                    log(f"FAIL {target}: {msg}")
            except Exception as e:
                log(f"ERROR {config[0]}: {e}")
                results.append((False, config[0], config[1], str(e)))

    # Summary
    successful = sum(1 for r in results if r[0])
    log(f"Build complete: {successful}/{len(results)} targets succeeded")

    # Create archives
    create_archives(results)


if __name__ == "__main__":
    main()
