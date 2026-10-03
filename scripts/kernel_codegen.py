"""Static codegen audit of the synthetic power kernels in built Windows x64 binaries.

Disassembles SynthKernel128/AVX2/AVX512 (located through the PDB) and reports
FMA count, widest register class, divides and 256/512-bit stack spills. Reads
binaries only; never runs a workload. Usage: python scripts/kernel_codegen.py [build...]
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNELS = ("SynthKernel128", "SynthKernelAVX2", "SynthKernelAVX512")
DEFAULT_BUILDS = ("x64-llvm", "x64-llvm-v3", "x64-llvm-v4", "x64-zig", "x64-zig-v3", "x64-msvc-v3")
# Windows x64 saves xmm6-15 as xmmword; only wider stack traffic is a spill.
WIDE_STACK = re.compile(r"[yz]mmword ptr \[rsp")
INSN = re.compile(r"^\s*[0-9a-f]+:\s")


def llvm_tools():
    for bin_dir in sorted((ROOT / "toolchains").glob("llvm-mingw-*/llvm-mingw-*/bin")):
        tools = bin_dir / "llvm-pdbutil.exe", bin_dir / "llvm-objdump.exe"
        if all(t.is_file() for t in tools):
            return tools
    return None


def kernel_ranges(pdbutil, pdb):
    """{kernel: (section-relative offset, size)} from the PDB's procedure records."""
    symbols = subprocess.run([str(pdbutil), "dump", "--symbols", str(pdb)], check=True,
                             capture_output=True, text=True).stdout
    ranges = {}
    for name in KERNELS:
        match = re.search(r"S_[GL]PROC32 \[size = \d+\] `(?:[^`]*[^A-Za-z0-9_])?" + name +
                          r"(?:[^A-Za-z0-9_][^`]*)?`\s*\n\s*parent = \d+, end = \d+, "
                          r"addr = 0001:(\d+), code size = (\d+)", symbols)
        if match:
            ranges[name] = int(match[1]), int(match[2])
    return ranges


def analyze(exe, tools):
    pdbutil, objdump = tools
    sections = subprocess.run([str(objdump), "-h", str(exe)], check=True,
                              capture_output=True, text=True).stdout
    text_va = int(re.search(r"\.text\s+[0-9a-f]+\s+([0-9a-f]+)", sections)[1], 16)
    report = {}
    for name, (offset, size) in kernel_ranges(pdbutil, exe.with_suffix(".pdb")).items():
        start = text_va + offset
        asm = subprocess.run([str(objdump), "-d", "--no-show-raw-insn", "--x86-asm-syntax=intel",
                              f"--start-address={start}", f"--stop-address={start + size}",
                              str(exe)], check=True, capture_output=True, text=True).stdout
        lines = [line for line in asm.splitlines() if INSN.match(line)]
        report[name] = {
            "insns": len(lines),
            "fma": sum(1 for line in lines if re.search(r"\tvfn?madd", line)),
            "widest": next((w for w in ("zmm", "ymm") if any(w in line for line in lines)), "xmm"),
            "div": sum(1 for line in lines if re.search(r"\tdiv\t", line)),
            "spills": [line.strip() for line in lines if WIDE_STACK.search(line)],
        }
    return report


def main(argv):
    tools = llvm_tools()
    if tools is None:
        print("llvm-pdbutil/llvm-objdump not found under toolchains/")
        return 1
    for build in argv or DEFAULT_BUILDS:
        exe = ROOT / "bin" / build / "ShaderStress.exe"
        if not exe.is_file() or not exe.with_suffix(".pdb").is_file():
            print(f"{build}: not built")
            continue
        for name, r in analyze(exe, tools).items():
            print(f"{build:18} {name:18} insns={r['insns']:4} fma={r['fma']:3} "
                  f"widest={r['widest']} div={r['div']} wide-spills={len(r['spills'])}")
            for line in r["spills"][:4]:
                print("    " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
