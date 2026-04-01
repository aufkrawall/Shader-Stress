# Shader Stress

Shader Stress is a CPU stress tool tuned to look more like shader and compiler workloads than a synthetic power virus. It supports a native Windows GUI and a cross-platform CLI for scripted or interactive runs.

<img width="572" height="556" alt="shaderstress" src="https://github.com/user-attachments/assets/3ba8410e-093d-43a4-9795-c5a820c03f5f" />

## Highlights

- Windows GUI for interactive monitoring and workload switching
- Cross-platform CLI for Windows, Linux, and macOS
- Dynamic, steady, benchmark, verification, and repro workflows
- ISA selection with automatic fallback across AVX-512, AVX2, and scalar paths
- Benchmark hash generation and validation
- Crash dump support on Windows and crash logging on Unix platforms
- Cross-compilation and archive packaging via Zig

## Supported Binaries

- Windows x64
- Windows x64 v3
- Windows ARM64
- Linux x64
- Linux x64 v3
- Linux ARM64
- macOS x64
- macOS ARM64

## Quick Start

### Windows GUI

Run `ShaderStress.exe` from Explorer or a shortcut with no arguments.

### Windows CLI

- Run `ShaderStress.com` from `cmd.exe`, PowerShell, or Windows Terminal with no arguments to open the CLI wizard.
- Run `ShaderStress.com --help` to see all CLI commands.
- Run `ShaderStress.com --benchmark` for the fixed 180-second benchmark flow. It defaults to `scalar-sim`, but you can override the ISA with `--isa`.
- `ShaderStress.exe` is the GUI launcher on Windows. `ShaderStress.com` is a tiny console launcher that forwards into the same application binary so GUI launch stays flash-free.

### Linux and macOS CLI

- Run `./shaderstress` with no arguments to open the CLI wizard.
- Run `./shaderstress --help` to see all CLI commands.

## Common Examples

```text
ShaderStress.com --mode steady --isa avx2 --duration 60
ShaderStress.com --benchmark
ShaderStress.com --verify SS3-XXXXXXXXXXXXXXXX
ShaderStress.com --repro 12345 1000 --isa scalar

./shaderstress --mode dynamic --duration 30 --quiet
./shaderstress --benchmark
./shaderstress --verify SS3-XXXXXXXXXXXXXXXX
```

## CLI Documentation

The full command-line contract, platform behavior, exit codes, and examples are documented in [cli-report.md](cli-report.md).

## Build

Shader Stress uses Zig for all builds and packaging.

### Requirements

- Python 3
- Zig 0.15.2 extracted under `zig-x86_64-windows-0.15.2/`

### Build Commands

```text
python build.py
python build.py windows
python build.py linux macos
python build.py native
```

The build script:

- reads the version from `VERSION`
- cross-compiles all configured targets
- writes release archives into `dist/`
- generates `dist/SHA256SUMS.txt`

## Logs and Output

- CLI and GUI sessions write `ShaderStress.log` in the working directory.
- CLI benchmark runs print the final benchmark hash when available.
- `--verify` returns a dedicated non-zero exit code when a hash is invalid.

## Notes

- CLI benchmark mode is fixed to 180 seconds and defaults to the `scalar-sim` workload for comparable hashes. You can override the ISA explicitly if needed.
- Windows ships one GUI-first executable plus a tiny `.com` launcher. This keeps the CLI path separate without duplicating the main binary.
- Release validation is still a manual process; build artifacts include checksums but there is no CI pipeline in this repository.
