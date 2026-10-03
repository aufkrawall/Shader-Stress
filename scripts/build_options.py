"""Target selection and comparison settings for build.py."""
import platform
import sys
from pathlib import Path

# Build configurations
# (target, out_dir, cpu, is_windows, archive_name, experimental)
# Experimental configs are only built when requested explicitly
# (`experimental` or their alias) and are never archived.
BUILD_CONFIGS = [
    # Windows (LLVM MinGW)
    ("x86_64-windows-gnu", "bin/x64-llvm", "x86_64", True, "ShaderStress-Windows-x64.7z", False),
    ("x86_64-windows-gnu", "bin/x64-llvm-v3", "x86_64_v3", True, "ShaderStress-Windows-x64-v3.7z", False),
    ("x86_64-windows-gnu", "bin/x64-llvm-v4", "x86_64_v4", True, "ShaderStress-Windows-x64-v4.7z", False),
    ("aarch64-windows-gnu", "bin/arm64-llvm", "generic", True, "ShaderStress-Windows-ARM64.7z", False),
    # Windows (Zig) - matches the historical GitHub release toolchain
    ("x86_64-windows-gnu", "bin/x64-zig", "x86_64", True, "ShaderStress-Windows-x64-Zig.7z", False),
    ("x86_64-windows-gnu", "bin/x64-zig-v3", "x86_64_v3", True, "ShaderStress-Windows-x64-v3-Zig.7z", False),
    ("aarch64-windows-gnu", "bin/arm64-zig", "generic", True, "ShaderStress-Windows-ARM64-Zig.7z", False),
    # Linux (Zig)
    ("x86_64-linux-gnu", "bin/linux-x64", "x86_64", False, "ShaderStress-Linux-x64.7z", False),
    ("x86_64-linux-gnu", "bin/linux-x64-v3", "x86_64_v3", False, "ShaderStress-Linux-x64-v3.7z", False),
    ("x86_64-linux-gnu", "bin/linux-x64-v4", "x86_64_v4", False, "ShaderStress-Linux-x64-v4.7z", False),
    ("aarch64-linux-gnu", "bin/linux-arm64", "generic", False, "ShaderStress-Linux-ARM64.7z", False),
    # macOS (Zig)
    ("x86_64-macos", "bin/macos-x64", "x86_64", False, "ShaderStress-macOS-x64.7z", False),
    ("aarch64-macos", "bin/macos-arm64", "generic", False, "ShaderStress-macOS-ARM64.7z", False),
    # Native MSVC comparison: built by all/windows when installed (required when
    # selected explicitly), never packaged so release archives stay host-independent.
    ("x86_64-windows-msvc", "bin/x64-msvc-v3", "x86_64_v3", True, "", False),
    # Experimental comparison builds (compiler-default loop unrolling)
    ("x86_64-windows-gnu", "bin/x64-llvm-v3-nounroll", "x86_64_v3", True, "", True),
    ("x86_64-windows-gnu", "bin/x64-zig-v3-nounroll", "x86_64_v3", True, "", True),
]

# Each comparison changes a single compiler setting; never package experiments.
# ("strictalias" is the pre-P007c -fno-strict-aliasing default, kept as the
# regression arm now that strict aliasing is the default.)
for variant in ("znver3", "nolto", "strictalias-off", "slp"):
    BUILD_CONFIGS.append(("x86_64-windows-gnu", "bin/x64-llvm-v3-" + variant,
                          "x86_64_v3", True, "", True))


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

def host_x86_level():
    """Best x86-64 level the build host can run: 'v4', 'v3' or 'baseline'."""
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            # PF_AVX512F_INSTRUCTIONS_AVAILABLE = 41, PF_AVX2_INSTRUCTIONS_AVAILABLE = 40
            if k32.IsProcessorFeaturePresent(41):
                return "v4"
            if k32.IsProcessorFeaturePresent(40):
                return "v3"
        except Exception:
            pass
        return "baseline"
    try:
        flags = Path("/proc/cpuinfo").read_text()
        if " avx512f" in flags:
            return "v4"
        if " avx2" in flags and " fma" in flags:
            return "v3"
    except Exception:
        pass
    return "baseline"


def print_help():
    print("Usage: python build.py [targets...] [options]")
    print("Targets:")
    print("  all           - All release targets (default)")
    print("  windows       - Windows release targets (LLVM MinGW + Zig + available MSVC)")
    print("  linux         - Linux x64 and ARM64")
    print("  macos         - macOS x64 and ARM64")
    print("  v4 / v3       - x86_64_v4 / x86_64_v3 release targets")
    print("  win-baseline  - Windows baseline x86_64 only (LLVM MinGW)")
    print("  win-v3        - Windows x86_64_v3 only")
    print("  win-v4        - Windows x86_64_v4 only")
    print("  zig           - Windows Zig-built x64 and ARM64")
    print("  zig-v3        - Windows Zig-built x86_64_v3 only")
    print("  msvc / msvc-v3 - Native MSVC x64 AVX2 comparison (auto-detected by all)")
    print("  win-v3-{nounroll,znver3,nolto,strictalias-off,slp} - One-setting comparisons")
    print("  native        - Best target this machine can run")
    print("  experimental  - Comparison builds (win-v3-nounroll, zig-v3-nounroll)")
    print("Options:")
    print("  --pgo-gen / --pgo-use       Profile-guided optimization (needs default.profdata)")
    print("  --sanitize                  UndefinedBehaviorSanitizer build (out dir suffix -ubsan)")
    print("  --sanitize=address          AddressSanitizer build (suffix -asan)")
    print("  --sanitize=thread           ThreadSanitizer build (suffix -tsan, Linux only)")
    print("Release builds emit debug symbols separately: ShaderStress.pdb (Windows),")
    print("shaderstress.debug (Linux). They are not part of the archives.")


def select_configs(targets_requested):
    release = [c for c in BUILD_CONFIGS if not c[5]]
    if "all" in targets_requested:
        return list(release)
    by_dir = {c[1]: c for c in BUILD_CONFIGS}
    aliases = {
        "win-baseline": ["bin/x64-llvm"],
        "win-v3": ["bin/x64-llvm-v3"],
        "win-v4": ["bin/x64-llvm-v4"],
        "zig-v3": ["bin/x64-zig-v3"],
        "win-v3-nounroll": ["bin/x64-llvm-v3-nounroll"],
        "zig-v3-nounroll": ["bin/x64-zig-v3-nounroll"],
        "experimental": [c[1] for c in BUILD_CONFIGS if c[5]],
    }
    aliases.update({Path(c[1]).name: [c[1]] for c in BUILD_CONFIGS})
    aliases.update({"win-v3-" + name: ["bin/x64-llvm-v3-" + name]
                    for name in ("znver3", "nolto", "strictalias-off", "slp")})
    aliases["win-v3-strictalias"] = ["bin/x64-llvm-v3-strictalias-off"]  # renamed in P007c
    aliases.update({name: ["bin/x64-msvc-v3"] for name in ("msvc", "msvc-v3")})
    configs = []
    for t in targets_requested:
        if t == "windows":
            configs += [c for c in release if "windows" in c[0]]
        elif t == "linux":
            configs += [c for c in release if "linux" in c[0]]
        elif t == "macos":
            configs += [c for c in release if "macos" in c[0]]
        elif t in ("v4", "v3"):
            configs += [c for c in release if c[1].endswith("-" + t)]
        elif t == "zig":
            configs += [c for c in release if "windows" in c[0] and "zig" in c[1]]
        elif t in aliases:
            configs += [by_dir[d] for d in aliases[t]]
        elif t == "native":
            system = platform.system().lower()
            machine = platform.machine().lower()
            level = host_x86_level()
            if system == "windows":
                if "arm" in machine or "aarch64" in machine:
                    configs.append(by_dir["bin/arm64-llvm"])
                else:
                    configs.append(by_dir[{"v4": "bin/x64-llvm-v4", "v3": "bin/x64-llvm-v3"}
                                          .get(level, "bin/x64-llvm")])
            elif system == "linux":
                if "arm" in machine or "aarch64" in machine:
                    configs.append(by_dir["bin/linux-arm64"])
                else:
                    configs.append(by_dir[{"v4": "bin/linux-x64-v4", "v3": "bin/linux-x64-v3"}
                                          .get(level, "bin/linux-x64")])
            elif system == "darwin":
                configs.append(by_dir["bin/macos-arm64" if "arm" in machine else "bin/macos-x64"])
        else:
            print(f"Unknown target '{t}' (use --help)")
            sys.exit(2)
    seen = set()
    unique = []
    for c in configs:
        if c[1] not in seen:
            seen.add(c[1])
            unique.append(c)
    return unique


