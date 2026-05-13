#!/usr/bin/env python3
"""
ShaderStress Build Script - Zig-only, maximum parallelism
Builds for all platforms using Zig cross-compilation
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
BUILD_CONFIGS = [
    # (target, out_dir, cpu, is_windows, archive_name)
    ("x86_64-windows-gnu", "bin/x64-zig", "x86_64", True, "ShaderStress-Windows-x64-Zig.7z"),
    ("x86_64-windows-gnu", "bin/x64-zig-v3", "x86_64_v3", True, "ShaderStress-Windows-x64-v3.7z"),
    ("x86_64-windows-gnu", "bin/x64-zig-v4", "x86_64_v4", True, "ShaderStress-Windows-x64-v4.7z"),
    ("aarch64-windows-gnu", "bin/arm64-zig", "generic", True, "ShaderStress-Windows-ARM64-Zig.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64", "x86_64", False, "ShaderStress-Linux-x64.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64-v3", "x86_64_v3", False, "ShaderStress-Linux-x64-v3.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64-v4", "x86_64_v4", False, "ShaderStress-Linux-x64-v4.7z"),
    ("aarch64-linux-gnu", "bin/linux-arm64", "generic", False, "ShaderStress-Linux-ARM64.7z"),
    ("x86_64-macos", "bin/macos-x64", "x86_64", False, "ShaderStress-macOS-x64.7z"),
    ("aarch64-macos", "bin/macos-arm64", "generic", False, "ShaderStress-macOS-ARM64.7z"),
]


def log(msg):
    print(f"[BUILD] {msg}", flush=True)


APP_VERSION_TEXT, APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH = load_version()


def check_zig():
    """Verify Zig is available"""
    if not ZIG_EXE.exists():
        log(f"ERROR: Zig not found at {ZIG_EXE}")
        log("Please download Zig 0.15.2 and extract to zig-x86_64-windows-0.15.2/")
        sys.exit(1)


def build_windows_cli_launcher(target, cpu, out_path):
    launcher_path = out_path / "ShaderStress.com"
    cmd = [
        str(ZIG_EXE), "cc",
        "-target", target,
    ]

    if cpu != "generic":
        cmd.extend(["-mcpu=" + cpu])

    cmd.extend([
        "-Oz", "-s",
        "-ffunction-sections", "-fdata-sections",
        "-fno-asynchronous-unwind-tables",
        "-fno-ident",
        "-municode",
        str(CLI_LAUNCHER_SOURCE),
        "-o", str(launcher_path),
        "-Xlinker", "--subsystem", "-Xlinker", "console",
        "-Xlinker", "--gc-sections",
    ])
    subprocess.run(cmd, check=True, capture_output=True)


# PGO mode: None, "generate", or "use"
PGO_MODE = None
# AVX2 workload variant (0-4); None = default (V1)
AVX2_VARIANT = None


def build_target(config):
    """Build a single target"""
    target, out_dir, cpu, is_windows, archive_name = config
    
    # Append variant suffix for AVX2 workload variants
    if AVX2_VARIANT is not None:
        out_dir = f"{out_dir}-avx2-v{AVX2_VARIANT}"
    
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)

    if is_windows:
        for stale_name in ["ShaderStress.com", "ShaderStressCli.exe", "ShaderStressGui.exe", "ShaderStressCli.cmd"]:
            stale_path = out_path / stale_name
            if stale_path.exists():
                stale_path.unlink()
    
    log(f"Starting {target} (cpu={cpu}){' avx2-v' + str(AVX2_VARIANT) if AVX2_VARIANT is not None else ''}...")
    
    src_files = SRC_FILES_WINDOWS[:] if is_windows else SRC_FILES_UNIX[:]
    defines = ["-DUNICODE", "-D_UNICODE"] if is_windows else ["-DPLATFORM_LINUX" if "linux" in target else "-DPLATFORM_MACOS"]
    
    if is_windows and "arm64" in target:
        defines.extend(["-D_M_ARM64", "-D_WIN64"])

    defines.extend([
        f'-DAPP_VERSION_TEXT="{APP_VERSION_TEXT}"',
        f"-DAPP_VERSION_MAJOR_NUM={APP_VERSION_MAJOR}",
        f"-DAPP_VERSION_MINOR_NUM={APP_VERSION_MINOR}",
        f"-DAPP_VERSION_PATCH_NUM={APP_VERSION_PATCH}",
    ])
    
    # Disable SEH for Zig (not supported)
    defines.append("-DDISABLE_SEH")
    
    # AVX2 workload variant (set via avx2-0..avx2-4 targets)
    if AVX2_VARIANT is not None:
        defines.append(f"-DAVX2_VARIANT={AVX2_VARIANT}")
    
    exe_name = "ShaderStress.exe" if is_windows else "shaderstress"
    exe_path = out_path / exe_name
    
    try:
        # Compile resource file for Windows (icon)
        if is_windows:
            res_file = out_path / "resource.res"
            rc_cmd = [
                str(ZIG_EXE), "rc",
                str(BASE_DIR / "resource.rc"),
                str(res_file)
            ]
            try:
                subprocess.run(rc_cmd, check=True, capture_output=True)
                src_files.append(str(res_file))
            except subprocess.CalledProcessError as e:
                log(f"Warning: Could not compile resource.rc for {target}: {e}")
        
        # Main build command
        # LTO supported on all targets except macOS (system linker ld doesn't support LLVM bitcode).
        # macOS builds skip LTO since Zig falls back to the system linker on that platform.
        use_lto = "macos" not in target
        
        base_cmd = [
            str(ZIG_EXE), "c++",
            "-target", target,
        ]
        
        # Add CPU target for architecture-specific optimizations BEFORE source files
        # This is crucial for v3 builds to enable AVX2, BMI, etc.
        if cpu != "generic":
            base_cmd.extend(["-mcpu=" + cpu])
        
        # Force 512-bit ZMM vector width on x86_64_v4 targets for maximum
        # power draw via wider auto-vectorization of init loops and non-hot code.
        if cpu == "x86_64_v4":
            base_cmd.append("-mprefer-vector-width=512")

        # Note: We do NOT add -mpopcnt/-mlzcnt/-mbmi for generic x86_64 builds
        # to maintain compatibility with older CPUs (pre-Haswell, pre-Nehalem).
        # The realistic workload may be slower on generic builds, but that's
        # the trade-off for broader compatibility. v3 builds target modern CPUs
        # and will automatically use these features via x86_64_v3.
        
        base_cmd.extend([
            "-std=c++20", "-O3",
            "-ffast-math", "-funroll-loops", "-funroll-all-loops", "-fpeel-loops",
            "-fno-rtti",
            # Disable C++ exceptions entirely (no try/catch in code, SEH compiled out)
            "-fno-exceptions",
            # Prevent symbol interposition allowing more aggressive inlining
            "-fno-semantic-interposition",
            # Register allocation improvements for better ILP
            "-frename-registers", "-fweb",
            # Remove stack canary checks (acceptable for stress tool)
            "-fno-stack-protector",
            # Free RBP as general-purpose register on x86-64
            "-fomit-frame-pointer",
            # Size optimizations - remove unused code/data
            "-ffunction-sections", "-fdata-sections",
            # Remove exception handling overhead (not used)
            "-fno-asynchronous-unwind-tables",
            # Remove compiler identification section
            "-fno-ident",
        ])
        
        if use_lto:
            base_cmd.append("-flto")
        
        # PGO: instrument for profile generation or use pre-generated profile
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
        
        if is_windows:
            base_cmd.append("-municode")
            # Enable Control Flow Guard on x86_64 Windows (defense-in-depth exploit mitigation).
            # ARM64 Windows does not support -fcf-protection in Zig 0.15.2.
            if "aarch64" not in target:
                base_cmd.append("-fcf-protection=full")
        
        base_cmd.extend(defines)
        base_cmd.extend(src_files)

        # Platform-specific link flags
        if is_windows:
            cmd = base_cmd[:] + [
                "-o", str(exe_path),
                "-Xlinker", "--subsystem", "-Xlinker", "windows",
                # Remove unused sections (requires -ffunction-sections/-fdata-sections)
                "-Xlinker", "--gc-sections",
                "-luser32", "-lgdi32", "-ldwmapi", "-lshcore",
                "-lshell32", "-lole32", "-ldbghelp"
            ]

            cmd = [c for c in cmd if c]
            subprocess.run(cmd, check=True, capture_output=True)
            build_windows_cli_launcher(target, cpu, out_path)
        else:
            cmd = base_cmd[:] + [
                "-o", str(exe_path),
                "-lpthread",
                # Sort common symbols and sections for improved cache locality
                "-Wl,--sort-common,--sort-section=alignment",
                # Remove unused sections (requires -ffunction-sections/-fdata-sections)
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
        
        # Check files exist
        if not all(f.exists() for f in src_files):
            return False
        
        try:
            if archive_path.exists():
                archive_path.unlink()
            
            if sevenzip:
                cmd = [sevenzip, "a", "-mx=9", str(archive_path)] + [str(f) for f in src_files]
                subprocess.run(cmd, check=True, capture_output=True)
            else:
                # Fallback to zip
                import zipfile
                zip_path = archive_path.with_suffix(".zip")
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                    for f in src_files:
                        zf.write(f, f.name)
            
            return True
        except Exception as e:
            log(f"Failed to create {archive_name}: {e}")
            return False
    
    # Create archives in parallel
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
    global PGO_MODE, AVX2_VARIANT
    check_zig()
    log(f"Version: {APP_VERSION_TEXT}")
    
    # Parse arguments
    targets_requested = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    
    # Extract PGO flags before other parsing
    if "--pgo-gen" in targets_requested:
        PGO_MODE = "generate"
        targets_requested.remove("--pgo-gen")
    if "--pgo-use" in targets_requested:
        PGO_MODE = "use"
        targets_requested.remove("--pgo-use")
    
    if "help" in targets_requested or "-h" in targets_requested or "--help" in targets_requested:
        print("Usage: python build.py [targets...] [options]")
        print("Targets:")
        print("  all       - All platforms (default)")
        print("  windows   - Windows x64 and ARM64")
        print("  linux     - Linux x64 and ARM64")
        print("  macos     - macOS x64 and ARM64")
        print("  v4        - x86_64_v4 targets (AVX-512) only")
        print("  native    - Current platform only")
        print("  avx2-0..4 - Build native x86_64 with specific AVX2 variant (0=lean, 1=current, 2=no-permute, 3=double-daisy, 4=wide-memory)")
        print("")
        print("Options:")
        print("  --pgo-gen  Build with profile generation instrumentation")
        print("  --pgo-use  Build with profile-guided optimization (needs default.profdata)")
        print("")
        print("PGO workflow:")
        print("  1. python build.py --pgo-gen native")
        print("  2. ./bin/<target>/shaderstress --repro 42 10000 --quiet")
        print("  3. llvm-profdata merge -output=default.profdata *.profraw")
        print("  4. python build.py --pgo-use native")
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
            elif t == "native":
                # Detect current platform and prefer highest CPU variant
                import platform
                machine = platform.machine().lower()
                system = platform.system().lower()
                if system == "windows":
                    candidates = [c for c in BUILD_CONFIGS if "windows" in c[0] and "x86_64" in c[0]]
                    for pref in ["v4", "v3", "zig"]:
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
            elif t.startswith("avx2-"):
                # Build native x86_64 with specific AVX2 variant (use v3 for best
                # AVX2+FMA support without AVX-512, which is ideal for Zen 3).
                import platform
                variant = int(t.split("-")[1])
                system = platform.system().lower()
                candidates = [c for c in BUILD_CONFIGS if "windows" in c[0] and "x86_64" in c[0]] if system == "windows" else [c for c in BUILD_CONFIGS if "linux" in c[0] and "x86_64" in c[0]]
                for pref in ["v3", "v4", "zig"]:
                    match = [c for c in candidates if pref in c[1]]
                    if match:
                        cfg = list(match[0])
                        configs.append(tuple(cfg))
                        AVX2_VARIANT = variant
                        break
    
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
