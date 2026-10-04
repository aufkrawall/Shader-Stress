"""Keep explicit SIMD kernels independent of automatic SLP and link-time rewrites."""
import subprocess
from pathlib import Path

KERNEL_SOURCES = (
    "src/workloads/SynthKernels.cpp",
    "src/workloads/SynthKernelsX86.cpp",
)


def compile_kernels(command, sources, out_path, root, slp=False):
    # Native objects prevent LTO from vectorizing the integer side again. Keep
    # explicit intrinsics, FP ordering, sanitizer instrumentation and symbols.
    omit = {"-flto", "-s", "-static", "-static-libstdc++", "-municode"}
    # Profiles trained on one host cannot cover every dispatched ISA. Keep the
    # hand-written kernels stable (including unsupported hot AVX-512 paths),
    # while the main program/realistic sim retain profile generation and use.
    flags = [arg for arg in command if arg not in omit and
             arg != "-fprofile-generate" and not arg.startswith("-fprofile-use=")]
    if any(arg == "-fprofile-generate" or arg.startswith("-fprofile-use=") for arg in command):
        print("[BUILD] PGO: main code profiled; native synthetic kernels keep unprofiled code", flush=True)
    flags += ["-fno-lto", "-ffp-contract=off"]
    if not slp:
        flags.append("-fno-slp-vectorize")
    result = list(sources)
    warnings = []
    for source in KERNEL_SOURCES:
        obj = out_path / (Path(source).stem + ".o")
        proc = subprocess.run(flags + ["-c", source, "-o", str(obj)],
                              check=True, capture_output=True, cwd=root)
        warnings.extend(line for line in proc.stderr.decode(errors="replace").splitlines()
                        if "warning:" in line)
        result[result.index(source)] = str(obj)
    return result, warnings
