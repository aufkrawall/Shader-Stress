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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Configuration
BASE_DIR = Path.cwd()
ZIG_DIR = BASE_DIR / "zig-x86_64-windows-0.15.2"
ZIG_EXE = ZIG_DIR / "zig.exe"

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
    ("aarch64-linux-gnu", "bin/linux-arm64", "generic", False, "ShaderStress-Linux-ARM64.7z"),
    ("x86_64-macos", "bin/macos-x64", "x86_64", False, "ShaderStress-macOS-x64.7z"),
    ("aarch64-macos", "bin/macos-arm64", "generic", False, "ShaderStress-macOS-ARM64.7z"),
]


def log(msg):
    print(f"[BUILD] {msg}", flush=True)


def check_zig():
    """Verify Zig is available"""
    if not ZIG_EXE.exists():
        log(f"ERROR: Zig not found at {ZIG_EXE}")
        log("Please download Zig 0.15.2 and extract to zig-x86_64-windows-0.15.2/")
        sys.exit(1)


def build_target(config):
    """Build a single target"""
    target, out_dir, cpu, is_windows, archive_name = config
    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    
    log(f"Starting {target} (cpu={cpu})...")
    
    src_files = SRC_FILES_WINDOWS[:] if is_windows else SRC_FILES_UNIX[:]
    defines = ["-DUNICODE", "-D_UNICODE"] if is_windows else ["-DPLATFORM_LINUX" if "linux" in target else "-DPLATFORM_MACOS"]
    
    if is_windows and "arm64" in target:
        defines.extend(["-D_M_ARM64", "-D_WIN64"])
    
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
        
        cmd = [
            str(ZIG_EXE), "c++",
            "-target", target,
            "-std=c++20", "-O3",
            "-ffast-math",
        ] + (["-flto"] if use_lto else []) + [
            "-s",
            "-Wno-macro-redefined",
        ] + (["-municode"] if is_windows else []) + defines + src_files
        
        cmd.extend([
            "-o", str(exe_path),
        ])
        
        # Platform-specific link flags
        if is_windows:
            cmd.extend([
                "-Xlinker", "--subsystem", "-Xlinker", "windows",
                "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", 
                "-lshell32", "-lole32", "-ldbghelp"
            ])
        else:
            cmd.append("-lpthread")
        
        # Remove empty strings
        cmd = [c for c in cmd if c]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        # Build CLI launcher for Windows
        if is_windows:
            com_path = out_path / "ShaderStress.com"
            # CLI launcher
            cmd_cli = [
                str(ZIG_EXE), "cc",
                "-target", target,
                "-x", "c",
                "-O2", "-s",
                "-Xlinker", "--subsystem", "-Xlinker", "console",
                "cli_launcher.c",
                "-o", str(com_path),
            ]
            subprocess.run(cmd_cli, check=True, capture_output=True)
        
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


def main():
    check_zig()
    
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
