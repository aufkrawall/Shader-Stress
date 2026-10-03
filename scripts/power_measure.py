"""Manual CPU power measurements. Never invoked with real workloads by unit tests."""
import argparse
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\.\d{3}\] Power sample: "
                    r"elapsed_ms=(\d+) watts=(\d+(?:\.\d+)?) jobs=(\d+)$")


def summarize_samples(log, warmup, duration, exit_code=0):
    if exit_code != 0:
        raise ValueError(f"workload exited with code {exit_code}; measurement rejected")
    samples = []
    previous_tick = -1
    for line in log.splitlines():
        match = SAMPLE.fullmatch(line.strip())
        if not match:
            continue  # Startup/status/final-summary readings are not samples.
        tick, watts, jobs = int(match[1]), float(match[2]), int(match[3])
        if not math.isfinite(watts) or not 0 < watts < 1000:
            raise ValueError("invalid power reading")
        if tick <= previous_tick:
            raise ValueError("duplicate/out-of-order acquisition timestamp")
        previous_tick = tick
        if warmup * 1000 <= tick < duration * 1000:
            samples.append((tick, watts, jobs))
    if len(samples) < 3:
        raise ValueError("fewer than three fresh post-warmup power readings")
    # Reject incomplete windows and sensor outages instead of averaging a few
    # surviving readings. The helper interval includes process/sensor startup.
    times = [warmup * 1000] + [s[0] for s in samples] + [duration * 1000]
    if any(b - a > 15000 for a, b in zip(times, times[1:])):
        raise ValueError("power sampling gap exceeds 15 seconds")
    if samples[-1][2] <= samples[0][2]:
        raise ValueError("no completed compute jobs during the measurement window")
    watts = [s[1] for s in samples]
    return {"Watts": round(statistics.mean(watts), 2),
            "StdDevW": round(statistics.stdev(watts), 2),
            "MinW": min(watts), "MaxW": max(watts), "Samples": len(samples),
            "FirstSampleMs": samples[0][0], "LastSampleMs": samples[-1][0],
            "JobsPerSecond": round((samples[-1][2] - samples[0][2]) * 1000 /
                                   (samples[-1][0] - samples[0][0]), 2)}


def workload_args(mode, duration, isa, threads):
    return ["--mode", mode, "--duration", str(duration), "--isa", isa,
            "--threads", str(threads), "--no-ram", "--no-io", "--no-decompress", "--quiet"]


def measure(exe, options, isa, evidence_root):
    exe = exe.resolve(strict=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=evidence_root))
    command = [str(exe), *workload_args(options.mode, options.duration, isa, options.threads)]
    with (run_dir / "console.log").open("wb") as output:
        try:
            result = subprocess.run(command, cwd=run_dir, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=options.duration + 120)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"measurement timed out; evidence: {run_dir}") from error
    log_path = run_dir / "ShaderStress.log"
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    try:
        summary = summarize_samples(log, options.warmup, options.duration, result.returncode)
    except ValueError as error:
        raise RuntimeError(f"{error}; evidence: {run_dir}") from error
    return {"ISA": isa, "Mode": options.mode, "Threads": options.threads,
            "Duration": options.duration, "Warmup": options.warmup,
            "Executable": str(exe), "SHA256": hashlib.sha256(exe.read_bytes()).hexdigest(),
            **summary, "Evidence": str(run_dir)}


def comma_values(value, convert=str):
    return [convert(v.strip()) for v in value.split(",") if v.strip()]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=ROOT / "bin/x64-llvm-v3/ShaderStress.com")
    parser.add_argument("--mode", choices=("benchmark", "steady"), default="benchmark")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--isas", default="avx2")
    parser.add_argument("--sweep", action="store_true")
    parser.add_argument("--targets", default="win-v3,zig-v3,msvc")
    parser.add_argument("--buffers", default="64,128,256,512")
    parser.add_argument("--rounds", default="2,4,8")
    parser.add_argument("--seed", type=int, default=42, help="reproducible candidate order")
    parser.add_argument("--csv", type=Path, default=ROOT / "sweep_results.csv")
    args = parser.parse_args(argv)
    if args.mode == "benchmark" and args.duration != 180:
        parser.error("benchmark duration is fixed at 180 seconds; use steady for shorter runs")
    if args.duration - args.warmup < 30 or args.warmup < 0:
        parser.error("allow at least 30 seconds after a nonnegative warmup")
    if args.threads < 1 or args.repeats < 1:
        parser.error("threads and repeats must be positive")
    args.isas = comma_values(args.isas)
    if not args.isas or any(i not in ("scalar", "scalar-sim", "avx2", "avx512") for i in args.isas):
        parser.error("invalid ISA list")
    try:
        args.buffers = comma_values(args.buffers, int)
        args.rounds = comma_values(args.rounds, int)
    except ValueError:
        parser.error("buffer sizes and rounds must be integer lists")
    # The stride stages require multiples of 32 KiB; that is the minimum
    # for the AVX-512 instantiation, even on an AVX2-only host.
    if not args.buffers or any(b < 32 or b > 16384 or b % 32 for b in args.buffers):
        parser.error("buffers must be multiples of 32 from 32 to 16384 KiB")
    if not args.rounds or any(r < 1 or r > 16 for r in args.rounds):
        parser.error("rounds must be in 1..16")
    return args


def main(argv=None):
    options = parse_args(argv)
    if sys.platform != "win32":
        raise RuntimeError("package power sampling currently requires Windows")
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("run from an elevated terminal to read CPU package power")
    evidence = ROOT / "audit/power-measurements"
    evidence.mkdir(parents=True, exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix="session-", dir=evidence))
    print(f"Manual full CPU load: {options.threads} threads, {options.mode}, "
          f"{options.duration}s/run, {options.repeats} repeats. Evidence: {session}", flush=True)
    print("Compare the same sensor; record temperature, effective clocks and PPT/TDC/EDC "
          "limits externally. Power gains are not inferred from throughput.", flush=True)
    rows = []
    options.csv = options.csv.resolve()
    if options.csv.exists():
        raise RuntimeError(f"refusing to replace existing results: {options.csv}; choose --csv")
    if options.sweep:
        # Import only configuration: no runtime workload and no toolchain discovery.
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from scripts.build_options import select_configs
        configs = select_configs(comma_values(options.targets))
        if any(not c[3] for c in configs):
            raise RuntimeError("power sweep targets must be Windows builds")
        candidates = list(itertools.product(configs, options.buffers, options.rounds))
        random.Random(options.seed).shuffle(candidates)
    else:
        candidates = [(None, None, None)]
    # Every repeat visits all candidates in a newly shuffled order. Tuning
    # binaries are isolated and rebuilt as necessary; release outputs stay intact.
    for repeat in range(1, options.repeats + 1):
        order = list(candidates)
        random.Random(options.seed + repeat).shuffle(order)
        for config, buf, rounds in order:
            exe = options.exe
            if config:
                target = config[1].removeprefix("bin/")
                env = dict(os.environ)
                env["SHADERSTRESS_EXTRA_DEFINES"] = f"-DSYNTH_BUF_KIB={buf} -DSYNTH_ROUNDS={rounds}"
                build_log = session / f"build-{target}-{buf}-{rounds}-{repeat}.log"
                with build_log.open("wb") as out:
                    result = subprocess.run([sys.executable, str(ROOT / "build.py"), target],
                                            cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise RuntimeError(f"build failed; evidence: {build_log}")
                exe = ROOT / (config[1] + "-tuning") / "ShaderStress.com"
            for isa in options.isas:
                print(f"Measuring {exe.parent.name}: {isa}, buffer={buf}, rounds={rounds}, "
                      f"repeat={repeat}", flush=True)
                row = {"Build": exe.parent.name, "BufKiB": buf, "Rounds": rounds,
                       "Repeat": repeat, **measure(exe, options, isa, session)}
                rows.append(row)
                # Save each completed run so later failures do not lose evidence.
                options.csv.parent.mkdir(parents=True, exist_ok=True)
                with options.csv.open("w", newline="", encoding="utf-8") as out:
                    writer = csv.DictWriter(out, fieldnames=list(row))
                    writer.writeheader()
                    writer.writerows(rows)
                print(f"  {row['Watts']} W (SD {row['StdDevW']} W, {row['Samples']} samples)", flush=True)
    (session / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Results: {options.csv}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
