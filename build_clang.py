import os
import sys
import subprocess
import shutil
import urllib.request
import tarfile
import glob

# Paths
BASE_DIR = os.getcwd()
MSYS_DIR = os.path.join(BASE_DIR, "msys64")
CLANG64_LIB = os.path.join(MSYS_DIR, "clang64", "lib", "clang", "21", "lib")
CLANG64_BIN = os.path.join(MSYS_DIR, "clang64", "bin")
CLANGARM64_DIR = os.path.join(MSYS_DIR, "clangarm64")
CLANGARM64_LIB_SRC = os.path.join(MSYS_DIR, "clangarm64", "lib", "clang", "21", "lib", "windows", "libclang_rt.builtins-aarch64.a")

CLANG_EXE = os.path.join(CLANG64_BIN, "clang++.exe")
WINDRES_EXE = os.path.join(CLANG64_BIN, "llvm-windres.exe")
MSYS_SHELL = os.path.join(MSYS_DIR, "usr", "bin", "bash.exe")

# Zig for cross-platform builds (Linux/macOS) - Official binary from ziglang.org
# MSYS2 package has LLVM/libc++ mismatch bug, use official instead
ZIG_EXE = os.path.join(BASE_DIR, "zig-x86_64-windows-0.15.2", "zig.exe")

# MSYS2 download URL
MSYS2_URL = "https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20240113.tar.xz"

# Required packages
PACKAGES = [
    "mingw-w64-clang-x86_64-toolchain",
    "mingw-w64-clang-aarch64-toolchain",
    "mingw-w64-clang-x86_64-zig",
    "base-devel"
]

# Source files for modular build (Windows includes Gui.cpp, others don't)
SRC_FILES_WINDOWS = [
    "Common.cpp", "CpuFeatures.cpp", "Platform.cpp", 
    "Workloads.cpp", "Threading.cpp", "Gui.cpp", "ShaderStress.cpp"
]
SRC_FILES_UNIX = [
    "Common.cpp", "CpuFeatures.cpp", "Platform.cpp",
    "Workloads.cpp", "Threading.cpp", "TerminalUtils.cpp", "ShaderStress.cpp"
]

def log(msg):
    print(f"[BUILD] {msg}")

def cleanup_build_artifacts():
    """Remove temporary build files (.o, .pdb) from bin folders"""
    patterns = [
        "bin/x64/*.o",
        "bin/x64/*.pdb",
        "bin/arm64/*.o",
        "bin/arm64/*.pdb",
        "bin/x64-zig/*.o",
        "bin/x64-zig/*.pdb",
        "bin/arm64-zig/*.o",
        "bin/arm64-zig/*.pdb",
    ]
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                os.remove(f)
                log(f"Cleaned up: {f}")
            except:
                pass

def create_zip_archives():
    """Create individual zip archives for each target using 7-Zip with ultra compression"""
    # Check for 7-Zip
    sevenzip = None
    for path in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]:
        if os.path.exists(path):
            sevenzip = path
            break
    
    targets = [
        ("bin/x64", "ShaderStress-Windows-x64.7z", ["ShaderStress.exe", "ShaderStress.com"]),
        ("bin/arm64", "ShaderStress-Windows-ARM64.7z", ["ShaderStress.exe", "ShaderStress.com"]),
        ("bin/x64-zig", "ShaderStress-Windows-x64-Zig.7z", ["ShaderStress.exe", "ShaderStress.com"]),
        ("bin/arm64-zig", "ShaderStress-Windows-ARM64-Zig.7z", ["ShaderStress.exe", "ShaderStress.com"]),
        ("bin/linux-x64", "ShaderStress-Linux-x64.7z", ["shaderstress"]),
        ("bin/linux-arm64", "ShaderStress-Linux-ARM64.7z", ["shaderstress"]),
        ("bin/macos-arm64", "ShaderStress-macOS-ARM64.7z", ["shaderstress"]),
        ("bin/macos-x64", "ShaderStress-macOS-x64.7z", ["shaderstress"]),
    ]
    
    dist_dir = "dist"
    if not os.path.exists(dist_dir):
        os.makedirs(dist_dir)
    
    for src_dir, archive_name, files in targets:
        archive_path = os.path.join(dist_dir, archive_name)
        if os.path.exists(archive_path):
            os.remove(archive_path)
        
        # Check if all required files exist
        src_files = [os.path.join(src_dir, f) for f in files]
        if not all(os.path.exists(f) for f in src_files):
            continue
        
        if sevenzip:
            # Use 7-Zip with ultra compression (-mx=9)
            cmd = [sevenzip, "a", "-mx=9", archive_path] + src_files
            try:
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL)
                log(f"Created: {archive_path}")
            except Exception as e:
                log(f"Failed to create {archive_path}: {e}")
        else:
            # Fallback to Python's shutil (zip format)
            zip_path = archive_path.replace(".7z", ".zip")
            import zipfile
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                for sf in src_files:
                    zf.write(sf, os.path.basename(sf))
            log(f"Created: {zip_path} (7-Zip not found, using zip)")

def run_msys_cmd(cmd):
    """Run a command in MSYS2 bash shell"""
    full_cmd = [MSYS_SHELL, "-l", "-c", cmd]
    subprocess.check_call(full_cmd)

def setup_msys2():
    """Download and setup MSYS2 with required packages"""
    if os.path.exists(CLANG_EXE):
        log("MSYS2 environment already set up.")
        return
    
    if not os.path.exists(MSYS_DIR):
        log(f"Downloading MSYS2 from {MSYS2_URL}...")
        tar_path = "msys2.tar.xz"
        urllib.request.urlretrieve(MSYS2_URL, tar_path)
        
        log("Extracting MSYS2 (this may take a few minutes)...")
        with tarfile.open(tar_path, "r:xz") as tar:
            tar.extractall()
        
        os.remove(tar_path)
        log("MSYS2 extracted.")
    
    # Initialize pacman
    log("Initializing pacman keys...")
    run_msys_cmd("pacman-key --init")
    run_msys_cmd("pacman-key --populate msys2")
    
    log("Updating package database...")
    run_msys_cmd("pacman -Sy --noconfirm")
    
    # Install packages
    log(f"Installing packages: {', '.join(PACKAGES)}")
    run_msys_cmd(f"pacman -S --needed --noconfirm {' '.join(PACKAGES)}")
    
    log("Setup complete!")

def ensure_env():
    """Ensure build environment is ready, setup if needed"""
    if not os.path.exists(CLANG_EXE):
        log("Clang not found. Running first-time setup...")
        setup_msys2()
        
        if not os.path.exists(CLANG_EXE):
            log(f"ERROR: Setup failed. Clang not found at {CLANG_EXE}")
            sys.exit(1)
    
    # Add clang bin to path for this process
    os.environ["PATH"] = CLANG64_BIN + os.pathsep + os.environ["PATH"]

def setup_arm64_libs():
    # Copy ARM64 builtins to where Clang x64 host expects them
    target_dir = os.path.join(CLANG64_LIB, "aarch64-w64-windows-gnu")
    target_file = os.path.join(target_dir, "libclang_rt.builtins.a")
    
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    if os.path.exists(CLANGARM64_LIB_SRC):
        log(f"Copying ARM64 runtime lib to {target_file}")
        shutil.copy2(CLANGARM64_LIB_SRC, target_file)
    else:
        log(f"WARNING: ARM64 source lib not found: {CLANGARM64_LIB_SRC}")

def copy_dlls(dest_dir):
    # Required DLLs for MinGW/Clang runtime
    dlls = ["libc++.dll", "libunwind.dll"] 
    for dll in dlls:
        src = os.path.join(CLANG64_BIN, dll)
        dst = os.path.join(dest_dir, dll)
        if os.path.exists(src):
            log(f"Copying {dll} to {dest_dir}")
            shutil.copy2(src, dst)
        else:
            log(f"WARNING: Could not find {dll} in {CLANG64_BIN}")

def build_x64():
    log("Building x64 Target...")
    out_dir = os.path.join("bin", "x64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)

    # Source Files - Modular build
    src_files = SRC_FILES_WINDOWS



    # 1. Compile Resource
    res_obj = os.path.join(out_dir, "resource.o")
    cmd_res = [WINDRES_EXE, "resource.rc", res_obj]
    subprocess.check_call(cmd_res)

    # 2. Compile Executable - Use baseline x86-64 for portability (no -march=native!)
    # LTO enabled for better optimization, -s to strip symbols for smaller binary
    cmd_build = [
        CLANG_EXE,
        "--target=x86_64-w64-mingw32",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto",  # Link-Time Optimization
        "-s",     # Strip symbols (smaller binary)
        "-municode", "-mwindows",
        "-static",  # Static linking
        "-DUNICODE", "-D_UNICODE", "-D_WIN32_WINNT=0x0A00",
        "-fms-extensions"] + src_files + [res_obj,
        "-o", os.path.join(out_dir, "ShaderStress.exe"),
        "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", "-lshell32", "-lole32", "-ldbghelp"
    ]

    
    log("Running Clang x64 (with LTO)...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.exe')}")

    # 3. Build CLI launcher (.com) - tiny stub that runs .exe
    cmd_build_cli = [
        CLANG_EXE,
        "--target=x86_64-w64-mingw32",
        "-x", "c",  # Force C mode (avoid warning about .c file in C++ mode)
        "-O2", "-s",
        "-mconsole",  # Console subsystem
        "-static",
        "cli_launcher.c",
        "-o", os.path.join(out_dir, "ShaderStress.com"),
    ]
    subprocess.check_call(cmd_build_cli)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.com')}")


def build_arm64():
    if not os.path.exists(CLANGARM64_DIR):
        log("Skipping ARM64 (Sysroot not found)")
        return

    setup_arm64_libs()
    log("Building ARM64 Target (Cross)...")
    out_dir = os.path.join("bin", "arm64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)



    # Source Files - Modular build
    src_files = SRC_FILES_WINDOWS



    # 1. Compile Resource
    res_obj = os.path.join(out_dir, "resource.o")
    inc_path = os.path.join(CLANGARM64_DIR, "aarch64-w64-mingw32", "include")
    
    cmd_res = [
        WINDRES_EXE, 
        "--target=aarch64-w64-mingw32", 
        f"-I{inc_path}",
        "resource.rc", res_obj
    ]
    subprocess.check_call(cmd_res)

    # 2. Compile Executable - LTO and stripping for smaller binary
    cmd_build = [
        CLANG_EXE,
        "--target=aarch64-w64-mingw32",
        f"--sysroot={CLANGARM64_DIR}",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto",  # Link-Time Optimization
        "-s",     # Strip symbols (smaller binary)
        "-DUNICODE", "-D_UNICODE",
        "-fms-extensions",
        "-municode", "-mwindows",
        "-static",  # Static linking for ARM64 too
        "-D_M_ARM64", "-D_WIN64"] + src_files + [res_obj,
        "-o", os.path.join(out_dir, "ShaderStress.exe"),
        "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", "-lshell32", "-lole32", "-ldbghelp"
    ]

    log("Running Clang ARM64 (with LTO)...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.exe')}")

    # 3. Build CLI launcher (.com) - tiny stub that runs .exe
    cmd_build_cli = [
        CLANG_EXE,
        "--target=aarch64-w64-mingw32",
        f"--sysroot={CLANGARM64_DIR}",
        "-x", "c",  # Force C mode
        "-O2", "-s",
        "-mconsole",  # Console subsystem
        "-static",
        "cli_launcher.c",
        "-o", os.path.join(out_dir, "ShaderStress.com"),
    ]
    subprocess.check_call(cmd_build_cli)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.com')}")


# ============================================================================
# Windows x64 Cross-Compile (via Zig) - for comparison testing
# ============================================================================
def build_x64_zig():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping Windows x64 Zig (Zig not found at {ZIG_EXE})")
        return False
    
    log("Building Windows x64 (via Zig)...")
    out_dir = os.path.join("bin", "x64-zig")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    # 1. Compile Resource using llvm-windres
    res_obj = os.path.join(out_dir, "resource.o")
    cmd_res = [WINDRES_EXE, "resource.rc", res_obj]
    subprocess.check_call(cmd_res)
    
    # 2. Build with Zig - same flags as other platforms for fair comparison
    # Use linker flag for GUI subsystem (no console window)
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "x86_64-windows-gnu",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto", "-s",  # LTO enabled with official Zig binary
        "-Wno-macro-redefined",  # Suppress _WIN32_WINNT redefinition warning
        "-DUNICODE", "-D_UNICODE",
        "-DDISABLE_SEH",  # __try/__except not supported by Zig
        "-municode",  # Use wWinMain entry point (Unicode)
        "-Xlinker", "--subsystem", "-Xlinker", "windows",  # GUI app - no console window
    ] + SRC_FILES_WINDOWS + [res_obj,
        "-o", os.path.join(out_dir, "ShaderStress.exe"),
        "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", "-lshell32", "-lole32", "-ldbghelp"
    ]
    
    log("Running Zig for Windows x64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.exe')}")
    
    # 3. Build CLI launcher (.com) - tiny stub that runs .exe
    cmd_build_cli = [
        ZIG_EXE, "cc",
        "-target", "x86_64-windows-gnu",
        "-x", "c",  # Force C mode
        "-O2", "-s",
        "-Xlinker", "--subsystem", "-Xlinker", "console",
        "cli_launcher.c",
        "-o", os.path.join(out_dir, "ShaderStress.com"),
    ]
    subprocess.check_call(cmd_build_cli)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.com')}")
    return True


# ============================================================================
# Windows ARM64 Cross-Compile (via Zig)
# ============================================================================
def build_arm64_zig():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping Windows ARM64 Zig (Zig not found at {ZIG_EXE})")
        return False
    
    log("Building Windows ARM64 (via Zig)...")
    out_dir = os.path.join("bin", "arm64-zig")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    # 1. Compile Resource using llvm-windres for ARM64
    res_obj = os.path.join(out_dir, "resource.o")
    cmd_res = [WINDRES_EXE, "--target=aarch64-w64-mingw32", "resource.rc", res_obj]
    subprocess.check_call(cmd_res)
    
    # 2. Build with Zig
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "aarch64-windows-gnu",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto", "-s",  # LTO enabled with official Zig binary
        "-Wno-macro-redefined",  # Suppress _WIN32_WINNT redefinition warning
        "-DUNICODE", "-D_UNICODE",
        "-D_M_ARM64", "-D_WIN64",
        "-DDISABLE_SEH",  # __try/__except not supported by Zig
        "-municode",  # Use wWinMain entry point (Unicode)
        "-Xlinker", "--subsystem", "-Xlinker", "windows",  # GUI app - no console window
    ] + SRC_FILES_WINDOWS + [res_obj,
        "-o", os.path.join(out_dir, "ShaderStress.exe"),
        "-luser32", "-lgdi32", "-ldwmapi", "-lshcore", "-lshell32", "-lole32", "-ldbghelp"
    ]
    
    log("Running Zig for Windows ARM64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.exe')}")
    
    # 3. Build CLI launcher (.com) - tiny stub that runs .exe
    cmd_build_cli = [
        ZIG_EXE, "cc",
        "-target", "aarch64-windows-gnu",
        "-x", "c",  # Force C mode
        "-O2", "-s",
        "-Xlinker", "--subsystem", "-Xlinker", "console",
        "cli_launcher.c",
        "-o", os.path.join(out_dir, "ShaderStress.com"),
    ]
    subprocess.check_call(cmd_build_cli)
    log(f"Success: {os.path.join(out_dir, 'ShaderStress.com')}")
    return True


# ============================================================================
# Linux x64 Cross-Compile (via Zig)
# ============================================================================
def build_linux_x64():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping Linux x64 (Zig not found at {ZIG_EXE})")
        log("Install with: pacman -S mingw-w64-clang-x86_64-zig")
        return False
    
    log("Building Linux x64 (cross-compile via Zig)...")
    out_dir = os.path.join("bin", "linux-x64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "x86_64-linux-gnu",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto", "-s",  # LTO enabled with official Zig binary
        "-DPLATFORM_LINUX",
    ] + SRC_FILES_UNIX + [
        "-o", os.path.join(out_dir, "shaderstress"),
        "-lpthread"
    ]
    
    log("Running Zig for Linux x64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'shaderstress')}")
    return True


# ============================================================================
# Linux ARM64 Cross-Compile (via Zig)
# ============================================================================
def build_linux_arm64():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping Linux ARM64 (Zig not found at {ZIG_EXE})")
        return False
    
    log("Building Linux ARM64 (cross-compile via Zig)...")
    out_dir = os.path.join("bin", "linux-arm64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "aarch64-linux-gnu",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-flto", "-s",  # LTO enabled with official Zig binary
        "-DPLATFORM_LINUX",
    ] + SRC_FILES_UNIX + [
        "-o", os.path.join(out_dir, "shaderstress"),
        "-lpthread"
    ]
    
    log("Running Zig for Linux ARM64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'shaderstress')}")
    return True


# ============================================================================
# macOS ARM64 Cross-Compile (via Zig)
# ============================================================================
def build_macos_arm64():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping macOS ARM64 (Zig not found at {ZIG_EXE})")
        log("Install with: pacman -S mingw-w64-clang-x86_64-zig")
        return False
    
    log("Building macOS ARM64 (cross-compile via Zig)...")
    out_dir = os.path.join("bin", "macos-arm64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "aarch64-macos",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-s",  # LTO unavailable for macOS (requires LLD linker)
        "-DPLATFORM_MACOS",
    ] + SRC_FILES_UNIX + [
        "-o", os.path.join(out_dir, "shaderstress"),
        "-lpthread"
    ]
    
    log("Running Zig for macOS ARM64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'shaderstress')}")
    return True


# ============================================================================
# macOS x64 Cross-Compile (via Zig) - Intel Macs
# ============================================================================
def build_macos_x64():
    if not os.path.exists(ZIG_EXE):
        log(f"Skipping macOS x64 (Zig not found)")
        return False
    
    log("Building macOS x64 (cross-compile via Zig)...")
    out_dir = os.path.join("bin", "macos-x64")
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    cmd_build = [
        ZIG_EXE, "c++",
        "-target", "x86_64-macos",
        "-std=c++20", "-O3",
        "-ffast-math",  # Fast floating point for stress testing
        "-s",  # LTO unavailable for macOS (requires LLD linker)
        "-DPLATFORM_MACOS",
    ] + SRC_FILES_UNIX + [
        "-o", os.path.join(out_dir, "shaderstress"),
        "-lpthread"
    ]
    
    log("Running Zig for macOS x64...")
    subprocess.check_call(cmd_build)
    log(f"Success: {os.path.join(out_dir, 'shaderstress')}")
    return True


def main():
    ensure_env()
    
    # Parse command line for target selection (default: all)
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    
    if "help" in targets or "-h" in targets or "--help" in targets:
        print("Usage: python build_clang.py [targets...]")
        print("Targets:")
        print("  all      - All platforms (default)")
        print("  zig      - Windows x64 via Zig (for comparison)")
        print("  linux    - Linux x64 (via Zig)")
        print("  macos    - macOS ARM64 + x64 (via Zig)")
        print("  all      - All platforms (includes zig)")
        print("\nExample: python build_clang.py windows linux macos")
        return
    
    if "all" in targets:
        targets = ["windows", "zig", "linux", "macos"]
    
    # Windows targets (via Clang/MinGW)
    if "windows" in targets:
        try:
            build_x64()
        except Exception as e:
            log(f"Windows x64 Build Failed: {e}")
        
        try:
            build_arm64()
        except Exception as e:
            log(f"Windows ARM64 Build Failed: {e}")
    
    # Windows via Zig (for comparison)
    if "zig" in targets:
        try:
            build_x64_zig()
        except Exception as e:
            log(f"Windows x64 Zig Build Failed: {e}")
        
        try:
            build_arm64_zig()
        except Exception as e:
            log(f"Windows ARM64 Zig Build Failed: {e}")
    
    # Linux targets (via Zig)
    if "linux" in targets:
        try:
            build_linux_x64()
        except Exception as e:
            log(f"Linux x64 Build Failed: {e}")
        
        try:
            build_linux_arm64()
        except Exception as e:
            log(f"Linux ARM64 Build Failed: {e}")
    
    # macOS targets (via Zig)
    if "macos" in targets:
        try:
            build_macos_arm64()
        except Exception as e:
            log(f"macOS ARM64 Build Failed: {e}")
        
        try:
            build_macos_x64()
        except Exception as e:
            log(f"macOS x64 Build Failed: {e}")
    
    # Cleanup and create archives
    cleanup_build_artifacts()
    create_zip_archives()

if __name__ == "__main__":
    main()

