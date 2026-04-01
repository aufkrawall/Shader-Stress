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
    ("aarch64-windows-gnu", "bin/arm64-zig", "generic", True, "ShaderStress-Windows-ARM64-Zig.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64", "x86_64", False, "ShaderStress-Linux-x64.7z"),
    ("x86_64-linux-gnu", "bin/linux-x64-v3", "x86_64_v3", False, "ShaderStress-Linux-x64-v3.7z"),
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


def build_target(config):
    """Build a single target"""
    target, out_dir, cpu, is_windows, archive_name = config
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)

    if is_windows:
        for stale_name in ["ShaderStress.com", "ShaderStressCli.exe", "ShaderStressGui.exe", "ShaderStressCli.cmd"]:
            stale_path = out_path / stale_name
            if stale_path.exists():
                stale_path.unlink()
    
    log(f"Starting {target} (cpu={cpu})...")
    
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
        # macOS doesn't support LTO with default linker
        use_lto = "macos" not in target
        
        base_cmd = [
            str(ZIG_EXE), "c++",
            "-target", target,
        ]
        
        # Add CPU target for architecture-specific optimizations BEFORE source files
        # This is crucial for v3 builds to enable AVX2, BMI, etc.
        if cpu != "generic":
            base_cmd.extend(["-mcpu=" + cpu])
        
        # Note: We do NOT add -mpopcnt/-mlzcnt/-mbmi for generic x86_64 builds
        # to maintain compatibility with older CPUs (pre-Haswell, pre-Nehalem).
        # The realistic workload may be slower on generic builds, but that's
        # the trade-off for broader compatibility. v3 builds target modern CPUs
        # and will automatically use these features via x86_64_v3.
        
        base_cmd.extend([
            "-std=c++20", "-O3",
            "-ffast-math", "-funroll-loops", "-fno-strict-aliasing",
            "-fno-rtti",
            # Size optimizations - remove unused code/data
            "-ffunction-sections", "-fdata-sections",
            # Remove exception handling overhead (not used)
            "-fno-asynchronous-unwind-tables",
            # Remove compiler identification section
            "-fno-ident",
        ])
        
        if use_lto:
            base_cmd.append("-flto")
        
        base_cmd.extend([
            "-s",
            "-Wno-macro-redefined",
        ])
        
        if is_windows:
            base_cmd.append("-municode")
        
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
            cmd = base_cmd[:] + ["-o", str(exe_path), "-lpthread"]
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
    check_zig()
    log(f"Version: {APP_VERSION_TEXT}")
    
    # Parse arguments
    targets_requested = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    
    if "help" in targets_requested or "-h" in targets_requested or "--help" in targets_requested:
        print("Usage: python build.py [targets...]")
        print("Targets:")
        print("  all       - All platforms (default)")
        print("  windows   - Windows x64 and ARM64")
        print("  linux     - Linux x64 and ARM64")
        print("  macos     - macOS x64 and ARM64")
        print("  native    - Current platform only")
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
            elif t == "native":
                # Detect current platform
                import platform
                machine = platform.machine().lower()
                system = platform.system().lower()
                if system == "windows":
                    configs.append([c for c in BUILD_CONFIGS if "windows" in c[0] and "x86_64" in c[0]][0])
                elif system == "linux":
                    configs.append([c for c in BUILD_CONFIGS if "linux" in c[0] and "x86_64" in c[0]][0])
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
