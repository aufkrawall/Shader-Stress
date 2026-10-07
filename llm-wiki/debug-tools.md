<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 aufkrawall
-->

# Debug and Binary Analysis Tools

This file is a reusable project-local tool inventory. Record tools and project-specific paths here when copying the template into a repository. Treat documented paths as hints until verified on the current machine.

## General rules

- Verify that a tool exists and runs before relying on it.
- Prefer repository-pinned or project-local tools when available.
- Prefer discovery (`Get-Command`, `where.exe`, `command -v`, tool manifests, environment variables) over stale hardcoded paths.
- Treat dumps, logs, captures, symbols, extracted strings, and diagnostic output as potentially sensitive.
- Do not mutate binaries, symbols, global debugger flags, registry/system settings, or persistent runtime configuration unless explicitly requested.
- When a preferred tool is unavailable, use a safe equivalent when practical and record the resulting coverage limitation.

## Tool/path resolution

For Windows projects using the default integration, `tools/discover-debug-tools.ps1` is the shared non-mutating discovery helper. Its generic machine-local output is `debug-tool-manifest.json`.

Use the first reliable source available:

1. generated `debug-tool-manifest.json`
2. local, uncommitted `tool-paths.env`
3. repository-local or pinned tool locations
4. shell discovery such as `Get-Command`, `where.exe`, or `command -v`
5. documented project-specific known-good paths
6. safe system defaults/fallbacks

The helper must not install packages, download tools, edit PATH, or mutate debugger/system state. If it is unavailable, use the remaining discovery sources directly.

## Project path variables

Projects may define equivalent variables in a local, uncommitted environment file:

```text
PROJECT_ROOT=
BUILD_ROOT=
INSTALL_ROOT=
SYMBOL_ROOT=
LOG_ROOT=
DUMP_ROOT=
CAPTURE_ROOT=
WINDOWS_SDK_DEBUGGERS_X86=
WINDOWS_SDK_DEBUGGERS_X64=
WINDOWS_SDK_DEBUGGERS_ARM=
WINDOWS_SDK_DEBUGGERS_ARM64=
MSVC_TOOLS_X86=
MSVC_TOOLS_X64=
MSVC_TOOLS_ARM64=
SYSINTERNALS_ROOT=
LLVM_ROOT=
FFMPEG_ROOT=
```

The reusable example lives at `common-tools/tool-paths.example.env` and is installed/merged into the target project's root path-override example. Use project-specific names if the repository already has established conventions.

## Windows debugging and binary analysis

Windows SDK Debugging Tools commonly live in architecture-specific subdirectories under `Windows Kits\10\Debuggers`, including `x64`, `x86`, `arm`, and `arm64`. The shared discovery helper generates candidates from `ProgramFiles(x86)` and `ProgramFiles`, preferring any matching `WINDOWS_SDK_DEBUGGERS_*` override first and falling back to PATH. Discover the variants relevant to the host and target instead of assuming x64, and record the resolved debugger architecture when it can affect live or remote debugging behavior.

Common tools, when installed:

| Tool | Purpose |
| --- | --- |
| `cdb.exe` | Command-line crash-dump debugging and stack inspection |
| `windbg.exe` / `WinDbgX.exe` | Interactive crash-dump and live debugging |
| `dumpchk.exe` | Dump readability and metadata validation |
| `symchk.exe` | Symbol validation/download |
| `dbh.exe` | PDB/symbol inspection |
| `pdbcopy.exe` / `symstore.exe` | Symbol-file handling and stores |
| `dumpbin.exe` / `link.exe /dump` | PE/COFF headers, imports, exports, sections, load config |
| `lib.exe /list` | Static-library member inspection |
| `undname.exe` | MSVC C++ symbol undecoration |
| `llvm-objdump.exe` | Object/binary inspection and disassembly |
| `llvm-strings.exe` / `strings.exe` | Printable-string inspection |
| `procdump.exe` | Process dump capture |
| `procmon.exe` | Process, registry, filesystem, and network activity tracing |
| `procexp.exe` | Process, handle, DLL, and thread inspection |
| `vmmap.exe` | Virtual-memory layout inspection |
| `handle.exe` | Open-handle inspection |
| `listdlls.exe` | Loaded-module inspection |
| `sigcheck.exe` | Signatures, versions, hashes, and related metadata |

Typical discovery commands:

```powershell
Get-Command cdb, windbg, dumpbin, llvm-objdump, procdump, procmon, sigcheck -ErrorAction SilentlyContinue
where.exe cdb.exe
where.exe dumpbin.exe
```

For crash dumps, use both public symbol servers and the relevant local/project symbol directory when local symbols are required. Example:

```powershell
cdb -z "$env:DUMP_ROOT\crash.dmp" -y "srv*;$env:SYMBOL_ROOT" -c ".ecxr; k; q"
```

Do not copy this command blindly: resolve the actual dump and symbol paths first.

## Linux debugging and binary analysis

Common tools:

| Tool | Purpose |
| --- | --- |
| `gdb` / `lldb` | Debugging and core analysis |
| `file` | Architecture and ABI identification |
| `readelf` | ELF headers, sections, symbols, program headers, dynamic metadata |
| `objdump` / `llvm-objdump` | Headers, disassembly, imports, sections |
| `nm` / `llvm-nm` | Symbol inspection |
| `strings` / `llvm-strings` | Embedded string inspection |
| `patchelf --print-rpath` | RPATH/RUNPATH inspection |
| `checksec` | Hardening summary |
| `strace` | Syscall tracing |

Prefer `readelf -d`, `objdump -p`, or equivalent static inspection for untrusted binaries. Use `ldd` only for trusted local build artifacts because loader-based dependency inspection can execute code in unsafe circumstances.

## macOS debugging and binary analysis

Common tools:

| Tool | Purpose |
| --- | --- |
| `lldb` | Debugging and crash analysis |
| `file` | Architecture and Mach-O identification |
| `otool` | Load commands and linked-library inspection |
| `lipo` | Universal-binary slice inspection |
| `codesign` | Signature, entitlement, and hardened-runtime metadata |
| `dwarfdump` | dSYM/debug-info inspection |
| `nm` / `strings` | Symbol and string inspection |
| `log` | Unified log inspection |
| `fs_usage` / `dtruss` | Runtime tracing where permitted |

For universal binaries, inspect each relevant architecture slice independently when architecture-specific behavior matters.

## Project-specific additions

Last verified: 2026-10-03. Stale-risk: medium (toolchain directory names change with
upgrades; keep in sync with `LLVM_MINGW_DIR` / `ZIG_DIR` in `build.py`).

### Symbols and artifacts

| Artifact | Location | Notes |
|---|---|---|
| Windows symbols | `bin/<target>/ShaderStress.pdb` | CodeView via `-g -gcodeview -Wl,--pdb=` (LLVM MinGW); Zig builds emit their own PDB. Exe is stripped. |
| Linux symbols | `bin/linux-*/shaderstress.debug` | Split with `llvm-objcopy --only-keep-debug`; binary carries a `.gnu_debuglink`. |
| macOS symbols | none | Stripped, no dSYM (coverage gap). |
| Crash report | `Crash_<date>_<time>_W<worker>/crash_info.txt` + `crash.dmp` in the working directory | Written by `CrashFilter` (`src/core/Platform.cpp`). Compact minidump (no full memory — RAM-test buffers would make it many GiB). Contains exception code, module offset, worker, logical CPU, workload, seed, complexity and a `--repro` line. |
| Unix crash | stderr `[CRASH]` block | `CrashSignalHandler` (`src/core/Platform.cpp`): signal, worker, CPU, workload, seed, repro line. |
| Run log | `ShaderStress.log` (working directory; `bin/test-work/` for test runs) | Topology, worker->CPU order, golden values, phase changes, per-minute health line, all CPU/RAM/I/O error details with suspect CPU. |
| Sanitizer builds | `bin/<target>-ubsan`, `-asan`, `-tsan` | `python build.py --sanitize[=address|thread] <target>`; ASan copies its runtime DLLs next to the exe. Run CLI modes (`--self-test`, `--repro`, ...) through the `ShaderStress.com` launcher in the same folder: `ShaderStress.exe` with CLI arguments shows a blocking "Use ShaderStress.com" message box on the user's desktop (seen 2026-10-07 with an `-asan` build). |

### Project-pinned LLVM tools

`toolchains/llvm-mingw-20260519-ucrt-x86_64/llvm-mingw-20260519-ucrt-x86_64/bin/` contains `lldb.exe`,
`llvm-objdump.exe`, `llvm-readobj.exe`, `llvm-nm.exe`, `llvm-pdbutil.exe`,
`llvm-symbolizer.exe`, `llvm-objcopy.exe`. Set `LLVM_ROOT` in `tool-paths.env` to use them
with `tools/discover-debug-tools.ps1`.

### Known-good commands

```text
# Always run CLI modes via ShaderStress.com (ShaderStress.exe + arguments pops a GUI message box).
# Symbolize an ASan frame without a debugger (module offset from the report):
llvm-addr2line -f -C -i -e bin/x64-llvm-asan/ShaderStress.exe 0x14003a1ee

# Find a UBSan/ASan report site (sanitizer runtimes also print to stderr):
lldb -b -o "breakpoint set -r __ubsan_handle_.*" -o run -o "bt 12" -- bin/x64-llvm-ubsan/ShaderStress.exe --repro 7 20 --isa scalar-sim
#   (set SHADERSTRESS_CLI_LAUNCHER=1 when starting ShaderStress.exe directly)

# Inspect a crash dump (Windows SDK debugger):
cdb -z Crash_<...>\crash.dmp -y "srv*;bin\x64-llvm" -c ".ecxr; k; q"     # unverified with lld PDBs

# DLL imports / runtime dependencies of a build:
llvm-objdump -p bin/x64-llvm-asan/ShaderStress.exe | grep "DLL Name"

# Re-run one failing job deterministically (prints the checksum, runs twice, exit 5 on mismatch):
ShaderStress.com --repro <seed> <complexity> --isa <isa>

# Single-thread kernel cost and health (no multi-thread stress):
ShaderStress.com --perf-stats

# Static kernel codegen audit (PDB + llvm-objdump, never runs a workload): FMA count,
# widest register, divides and ymm/zmm stack spills per kernel and build:
python scripts/kernel_codegen.py [x64-llvm-v3 x64-zig-v3 x64-msvc-v3 ...]
```

### Diagnostic-only behaviour

- `UBSAN_OPTIONS` uses `:` as separator, so Windows paths in `log_path=C:\...` break it;
  rely on stderr instead.
- `vendor/lhm/install-pawnio.ps1` / `uninstall-pawnio.ps1` install/remove a kernel driver —
  never run them during tests or diagnosis unless explicitly asked. The app itself
  auto-installs PawnIO only when started elevated with the `lhm/` folder present.
- `SHADERSTRESS_EXTRA_DEFINES` (env) forwards `-D` kernel knobs to every compile
  (also MSVC as `/D`); builds then go to `<out>-tuning` and are never archived, so
  release binaries stay intact (`scripts/power_measure.py --sweep`).
