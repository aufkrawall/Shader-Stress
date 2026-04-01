# CLI Report

## Overview

ShaderStress ships with one command-line interface across Windows, Linux, and macOS.
The CLI has two operating styles:

- Interactive wizard for manual terminal use
- Explicit non-interactive commands for scripting and repeatable runs

Windows ships one GUI executable plus a tiny `.com` launcher for the CLI path.

## Launch Behavior

### Windows

- `ShaderStress.exe` is the GUI executable. Start it from Explorer or a shortcut to open the GUI with no console flash.
- `ShaderStress.com` is the CLI launcher. Start it from `cmd.exe`, PowerShell, or Windows Terminal to use the interactive wizard or explicit CLI commands.
- `ShaderStress.exe` is not the supported CLI entry point on Windows. If it is launched with CLI arguments, it tells the user to switch to `ShaderStress.com`.

### Linux and macOS

- `./shaderstress` with no arguments opens the CLI wizard.
- If the wizard is needed but the process is not attached to a terminal, ShaderStress tries to spawn one unless `--force-no-spawn` is used.
- Explicit non-interactive commands such as `--help`, `--mode`, `--benchmark`, `--verify`, and `--repro` do not depend on the wizard.

## Supported Commands

| Command | Arguments | Interactive | Platforms | Notes |
| --- | --- | --- | --- | --- |
| `--wizard` | none | yes | Windows `.com` launcher, Linux, macOS | Forces the interactive CLI wizard. |
| `--mode` | `dynamic`, `steady`, `benchmark` | no | Windows `.com` launcher, Linux, macOS | Starts a run without prompting. |
| `--benchmark` | none | no | Windows `.com` launcher, Linux, macOS | Shortcut for benchmark mode. |
| `--verify` | `<hash>` | no | Windows `.com` launcher, Linux, macOS | Validates and decodes a benchmark hash. |
| `--repro` | `<seed> <complexity>` | no | Windows `.com` launcher, Linux, macOS | Runs a single reproducible workload case. |
| `--help` | none | no | Windows `.com` launcher, Linux, macOS | Prints CLI usage. |
| `--version` | none | no | Windows `.com` launcher, Linux, macOS | Prints the app version. |

## Run Options

| Option | Arguments | Applies To | Notes |
| --- | --- | --- | --- |
| `--isa` | `auto`, `avx512`, `avx2`, `scalar`, `scalar-sim` | run commands, `--repro`, wizard defaults | Benchmark mode defaults to `scalar-sim` when ISA is not specified. |
| `--duration` | `<seconds>` | non-benchmark runs | Stops the run after the specified duration. |
| `--max-duration` | `<seconds>` | non-benchmark runs | CLI alias for `--duration`. If both are supplied they must match. |
| `--no-avx512` | none | run and repro commands | Prevents AVX-512 selection and fallback resolution. |
| `--no-avx2` | none | run and repro commands | Prevents AVX2 selection and fallback resolution. |
| `--quiet` | none | run and repro commands | Suppresses the live dashboard and startup banner. Final results still print. |
| `--force-no-spawn` | none | Linux and macOS | Disables terminal auto-spawn for wizard-style startup. |

## Wizard Behavior

The wizard is intentionally limited to interactive terminal sessions.

- Empty input in the wizard uses the displayed default.
- Closed stdin or non-terminal stdin does not silently choose defaults.
- The wizard can start `dynamic`, `steady`, or `benchmark` runs.
- The wizard can also switch into hash verification.
- In benchmark mode the wizard prompts for ISA. The default is `scalar-sim` for comparable hashes, but you can choose another workload.

## Defaults and Safety Rules

- No-argument terminal launch enters the wizard.
- A no-argument graphical Windows launch opens the GUI, not a background stress run.
- Modifier-only invocations such as `--isa avx2` or `--no-avx512` are rejected unless paired with an explicit action like `--wizard`, `--mode`, `--duration`, `--benchmark`, `--verify`, or `--repro`.
- Unknown flags are rejected.
- Missing values for flags that require arguments are rejected.
- Benchmark mode is fixed to 180 seconds. If no ISA is specified, it defaults to `scalar-sim`.
- `--verify` is mutually exclusive with run and wizard options.
- `--repro` is mutually exclusive with wizard, benchmark, and duration options.

## Output and Logging

- Runtime logs are written to `ShaderStress.log` in the current working directory.
- Interactive terminal sessions show a live ANSI dashboard unless `--quiet` is used.
- Non-interactive output remains plain text and ends with final summary lines.
- Benchmark runs print the final benchmark hash when available.
- `--verify` prints decoded hash contents and returns a dedicated exit code if validation fails.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Invalid arguments |
| `3` | Environment or setup error |
| `4` | Benchmark hash verification failed |
| `130` | Interrupted by Ctrl+C or termination signal |

## Examples

### Interactive wizard

```text
ShaderStress.com
./shaderstress
ShaderStress.com --wizard
```

### Timed steady run

```text
ShaderStress.com --mode steady --isa avx2 --duration 60
./shaderstress --mode steady --isa avx2 --duration 60
```

### Fixed benchmark

```text
ShaderStress.com --benchmark
./shaderstress --benchmark
```

### Quiet batch run

```text
ShaderStress.com --mode dynamic --duration 30 --quiet
./shaderstress --mode dynamic --duration 30 --quiet
```

### Hash verification

```text
ShaderStress.com --verify SS3-XXXXXXXXXXXXXXXX
./shaderstress --verify SS3-XXXXXXXXXXXXXXXX
```

### Reproduction run

```text
ShaderStress.com --repro 12345 1000 --isa scalar
./shaderstress --repro 12345 1000 --isa scalar
```

## Build and Release Notes

- `build.py` packages `ShaderStress.exe` for the GUI and `ShaderStress.com` as the Windows CLI launcher.
- The build script reads version metadata from `VERSION`.
- Release archives are written to `dist/`.
