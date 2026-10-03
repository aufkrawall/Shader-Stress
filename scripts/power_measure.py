"""Manual CPU power measurements: package power, effective clock, temperature, Vcore.

Never invoked with real workloads by unit tests (full CPU load). Elevates itself
via UAC when needed (PawnIO sensors). Workflow and decision rules:
llm-wiki/power-optimization.md; results ledger: llm-wiki/power-ledger.md.

    # A/B: baseline snapshot vs current build, interleaved, all three target ISAs
    # (default short mode: 30 s preheat, then 8 s warmup + 15 s window per run, 5 repeats)
    python scripts/power_measure.py --snapshot P001-base
    python scripts/power_measure.py --label P001-my-change \\
        --exe audit/power-baselines/P001-base/ShaderStress.com,bin/x64-llvm-v3/ShaderStress.com
    # Confirm absolute numbers in the real 180 s benchmark
    python scripts/power_measure.py --mode benchmark --label P001-confirm
    # Buffer x rounds x compiler sweep (isolated -tuning builds)
    python scripts/power_measure.py --sweep --targets win-v3 --buffers 128,512 --rounds 2,4
    # Re-summarize an existing CSV
    python scripts/power_measure.py --summarize audit/power-measurements/<session>/results.csv
"""
import argparse
import csv
import hashlib
import itertools
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import power_host  # noqa: E402  (needs ROOT on sys.path)

EVIDENCE = ROOT / "audit/power-measurements"
BASELINES = ROOT / "audit/power-baselines"
TARGET_ISAS = "scalar-sim,scalar,avx2"  # realistic sim, SSE2 synthetic, AVX2 synthetic
SWEEP_ISAS = "scalar,avx2"              # SYNTH_* knobs do not affect the realistic sim
NUM = r"(-?\d+(?:\.\d+)?)"
SAMPLE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\.\d{3}\] Power sample: "
                    r"elapsed_ms=(\d+) watts=(\d+(?:\.\d+)?) jobs=(\d+)"
                    rf"(?: eff_mhz={NUM} temp_c={NUM} vcore_v={NUM})?$")
# Two-sided 95% Student-t quantiles by degrees of freedom (paired repeats - 1).
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
       9: 2.262, 10: 2.228}
MIN_POWER_DELTA_W = 1.0      # smaller power deltas are never acted on
MIN_CLOCK_DELTA_MHZ = 15.0   # smaller clock deltas never decide a tie
# Per mode: ShaderStress run, warmup, measurement window, repeats, preheat.
# "short" = steady mode with every thread on compute: the same worker layout
# as the benchmark (SetWork(cpu, 0)), fixed 12k-complexity jobs instead of the
# benchmark's 5k-500k mix. It screens A/B differences; "benchmark" confirms
# absolute numbers in the user's 180 s scenario.
MODE_DEFAULTS = {"short": {"warmup": 8, "measure": 15, "repeats": 5, "preheat": 30},
                 "benchmark": {"warmup": 30, "measure": 148, "repeats": 3, "preheat": 0}}
BENCHMARK_SECONDS = 180
NUMERIC = {"BufKiB": int, "Rounds": int, "Repeat": int, "Threads": int, "Samples": int,
           "Watts": float, "StdDevW": float, "MinW": float, "MaxW": float,
           "JobsPerSecond": float, "EffMHz": float, "TempMeanC": float, "TempMaxC": float,
           "VcoreV": float, "BackgroundLoadPct": float}


def sensor(value):
    """Optional log field: None when absent or reported unavailable (-1)."""
    if value is None:
        return None
    v = float(value)
    return v if math.isfinite(v) and v > 0 else None


def mean_or_none(values, digits):
    values = [v for v in values if v is not None]
    return round(statistics.mean(values), digits) if values else None


def summarize_samples(log, warmup, measure, exit_code=0, interval=1.0, max_gap=3.0):
    """Mean of the readings whose window lies in [warmup, warmup + measure] s.

    Each reading averages the `interval` s before its timestamp (PowerReader
    --stream: contiguous windows), so complete coverage averages energy.
    """
    if exit_code != 0:
        raise ValueError(f"workload exited with code {exit_code}; measurement rejected")
    samples = []
    previous_tick = -1
    first_ms = round((warmup + interval) * 1000)  # first window starting after warmup
    end_ms = round((warmup + measure) * 1000)
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
        if first_ms <= tick <= end_ms:
            samples.append((tick, watts, jobs, sensor(match[4]), sensor(match[5]),
                            sensor(match[6])))
    # Reject incomplete windows and sensor outages instead of averaging a few
    # surviving readings (binaries before 1 s streaming sampled every ~6.5 s:
    # use --sample-interval 6.5 --max-gap 15 for them).
    expected = measure / interval
    if len(samples) < max(3, math.floor(0.8 * expected)):
        raise ValueError(f"only {len(samples)} power readings in the {measure} s window "
                         f"(expected ~{expected:.0f})")
    times = [first_ms] + [s[0] for s in samples] + [end_ms]
    gap = max(b - a for a, b in zip(times, times[1:]))
    if gap > max_gap * 1000:
        raise ValueError(f"power sampling gap of {gap / 1000:.1f} s exceeds {max_gap} s")
    if samples[-1][2] <= samples[0][2]:
        raise ValueError("no completed compute jobs during the measurement window")
    watts = [s[1] for s in samples]
    temps = [s[4] for s in samples if s[4] is not None]
    return {"Watts": round(statistics.mean(watts), 2),
            "StdDevW": round(statistics.stdev(watts), 2),
            "MinW": min(watts), "MaxW": max(watts), "Samples": len(samples),
            "FirstSampleMs": samples[0][0], "LastSampleMs": samples[-1][0],
            "JobsPerSecond": round((samples[-1][2] - samples[0][2]) * 1000 /
                                   (samples[-1][0] - samples[0][0]), 2),
            "EffMHz": mean_or_none([s[3] for s in samples], 0),
            "TempMeanC": mean_or_none(temps, 1), "TempMaxC": max(temps) if temps else None,
            "VcoreV": mean_or_none([s[5] for s in samples], 3)}


def run_seconds(mode, warmup, measure):
    return BENCHMARK_SECONDS if mode == "benchmark" else math.ceil(warmup + measure) + 2


def workload_args(mode, seconds, isa, threads):
    # threads 0 = all logical CPUs, exactly like a user's benchmark run.
    if mode == "benchmark":
        args = ["--mode", "benchmark", "--isa", isa]  # fixed 180 s
    else:
        args = ["--mode", "steady", "--duration", str(seconds), "--isa", isa]
    if threads:
        args += ["--threads", str(threads)]
    return args + ["--no-ram", "--no-io", "--no-decompress", "--quiet"]


def binary_sha256(exe):
    """Hash of the workload binary: ShaderStress.com is only the CLI launcher."""
    exe = Path(exe)
    target = exe.with_name("ShaderStress.exe") if exe.name.lower() == "shaderstress.com" else exe
    target = target if target.exists() else exe
    return hashlib.sha256(target.read_bytes()).hexdigest()


def make_evidence_dir(parent, prefix):
    """Creates an evidence directory inheriting the parent's DACL.

    tempfile.mkdtemp() applies a 0o700 mode that Windows maps to an
    owner-only DACL; when the elevated child creates it, the unelevated
    parent shell loses access. A plain mkdir() inherits audit/'s DACL
    (Administrators full access + the user's own entries), readable from
    both tokens. Retries on collision: the stamp makes it unique.
    """
    parent = Path(parent)
    for attempt in range(100):
        candidate = parent / f"{prefix}{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{attempt:02d}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise FileExistsError(f"no usable evidence directory name under {parent}")


def git(*args):
    try:
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None


def run_workload(exe, mode, seconds, isa, threads, run_dir):
    command = [str(exe.resolve(strict=True)), *workload_args(mode, seconds, isa, threads)]
    with (run_dir / "console.log").open("wb") as output:
        try:
            result = subprocess.run(command, cwd=run_dir, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=seconds + 120)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"workload timed out; evidence: {run_dir}") from error
    log_path = run_dir / "ShaderStress.log"
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    return result.returncode, log


def measure(exe, options, isa, session, label, repeat):
    parent = Path(session)
    run_dir = None
    for attempt in range(100):
        candidate = parent / f"run-{label}-{isa}-r{repeat}-{attempt:02d}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        run_dir = candidate
        break
    if run_dir is None:
        raise FileExistsError(f"no usable run directory name under {parent}")
    seconds = run_seconds(options.mode, options.warmup, options.measure)
    code, log = run_workload(exe, options.mode, seconds, isa, options.threads, run_dir)
    try:
        summary = summarize_samples(log, options.warmup, options.measure, code,
                                    options.sample_interval, options.max_gap)
    except ValueError as error:
        raise RuntimeError(f"{error}; evidence: {run_dir}") from error
    return {"ISA": isa, "Mode": options.mode, "Threads": options.threads or os.cpu_count(),
            "RunSeconds": seconds, "Warmup": options.warmup, "Measure": options.measure,
            "Executable": str(exe.resolve()), "SHA256": binary_sha256(exe), **summary,
            "Evidence": str(run_dir)}


def preheat(exe, options, session):
    """Unrecorded load so the cooler is warm before the first measured run."""
    isa = "avx2" if "avx2" in options.isas else options.isas[0]
    run_dir = session / "preheat"
    run_dir.mkdir()
    print(f"Preheat: {exe.parent.name} {isa} for {options.preheat} s (not recorded)", flush=True)
    code, _ = run_workload(exe, "short", options.preheat, isa, options.threads, run_dir)
    if code != 0:
        raise RuntimeError(f"preheat run exited with code {code}; evidence: {run_dir}")


def snapshot(label, source, dest_root=BASELINES):
    """Copies a built output directory so later builds cannot change the baseline."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label):
        raise ValueError("snapshot label: letters, digits, '.', '_', '-' (max 64)")
    source = Path(source)
    if not (source / "ShaderStress.com").exists() or not (source / "ShaderStress.exe").exists():
        raise RuntimeError(f"no built ShaderStress.com/.exe in {source}")
    dest = Path(dest_root) / label
    if dest.exists():
        raise RuntimeError(f"snapshot already exists: {dest}")
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns("*.log", "Crash_*", "run-*"))
    status = git("status", "--porcelain")
    meta = {"Label": label, "Source": str(source), "Created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "GitHead": (git("rev-parse", "HEAD") or "").strip() or None,
            "GitDirty": bool(status and status.strip()),
            "SHA256": binary_sha256(dest / "ShaderStress.com")}
    if meta["GitDirty"]:
        # Exactly what was measured, so a ledger entry can name its change.
        (dest / "changes.patch").write_text(git("diff", "HEAD") or "", encoding="utf-8")
        meta["GitStatus"] = status.splitlines()
    (dest / "SNAPSHOT.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return dest


def paired_delta(base_runs, cand_runs, key):
    """Mean and 95% CI half-width of per-repeat differences (cancels drift)."""
    base = {r["Repeat"]: r.get(key) for r in base_runs}
    diffs = [r[key] - base[r["Repeat"]] for r in cand_runs
             if r.get(key) is not None and base.get(r["Repeat"]) is not None]
    if not diffs:
        return None, None, 0
    if len(diffs) < 2:
        return statistics.mean(diffs), None, len(diffs)
    t = T95.get(len(diffs) - 1, T95[10])
    return statistics.mean(diffs), t * statistics.stdev(diffs) / math.sqrt(len(diffs)), len(diffs)


def verdict(dw, dw_ci, de, de_ci):
    """Higher package power is better; at equal power a lower effective clock wins."""
    if dw is None or dw_ci is None:
        return "inconclusive (needs >= 2 paired repeats)"
    if abs(dw) > dw_ci and abs(dw) >= MIN_POWER_DELTA_W:
        return "better (more power)" if dw > 0 else "worse (less power)"
    if de is not None and de_ci is not None and abs(de) > de_ci and abs(de) >= MIN_CLOCK_DELTA_MHZ:
        return ("tie-break better (same power, lower eff clock)" if de < 0
                else "tie-break worse (same power, higher eff clock)")
    return "inconclusive (within noise)"


def candidate_name(row):
    if row.get("BufKiB") in (None, ""):
        return row["Build"]
    return f"{row['Build']} buf={row['BufKiB']} rounds={row['Rounds']}"


def summarize_runs(rows, baseline=None, temp_limit=90.0):
    groups = {}
    for row in rows:
        groups.setdefault((candidate_name(row), row["ISA"]), []).append(row)
    names = list(dict.fromkeys(name for name, _ in groups))
    if baseline and baseline not in names:
        raise ValueError(f"baseline {baseline!r} not among candidates: {', '.join(names)}")
    base = baseline or (names[0] if names else None)
    entries = []
    for (name, isa), runs in groups.items():
        watts = [r["Watts"] for r in runs]
        temps = [r.get("TempMaxC") for r in runs if r.get("TempMaxC") is not None]
        entry = {"Candidate": name, "ISA": isa, "Runs": len(runs),
                 "Watts": round(statistics.mean(watts), 2),
                 "WattsSD": round(statistics.stdev(watts), 2) if len(watts) > 1 else None,
                 "EffMHz": mean_or_none([r.get("EffMHz") for r in runs], 0),
                 "TempMaxC": max(temps) if temps else None,
                 "VcoreV": mean_or_none([r.get("VcoreV") for r in runs], 3),
                 "JobsPerSecond": mean_or_none([r.get("JobsPerSecond") for r in runs], 1),
                 "ThermalLimit": bool(temps) and max(temps) >= temp_limit - 1}
        if name != base and (base, isa) in groups:
            dw, dw_ci, n = paired_delta(groups[(base, isa)], runs, "Watts")
            de, de_ci, _ = paired_delta(groups[(base, isa)], runs, "EffMHz")
            entry.update({"Baseline": base, "Pairs": n,
                          "DeltaW": None if dw is None else round(dw, 2),
                          "DeltaWCI95": None if dw_ci is None else round(dw_ci, 2),
                          "DeltaEffMHz": None if de is None else round(de),
                          "DeltaEffCI95": None if de_ci is None else round(de_ci),
                          "Verdict": verdict(dw, dw_ci, de, de_ci)})
        entries.append(entry)
    return entries


def format_summary(entries):
    def f(v, spec=""):
        return "-" if v is None else format(v, spec)

    def delta(v, ci, spec):
        return "-" if v is None else f"{v:+{spec}}" + ("" if ci is None else f" +-{ci:{spec}}")
    lines = ["| Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) "
             "| Tmax C | Vcore | Jobs/s | Verdict |", "|" + "---|" * 11]
    for e in entries:
        lines.append(f"| {e['Candidate']} | {e['ISA']} | {e['Runs']} | {e['Watts']:.1f} "
                     f"({f(e['WattsSD'], '.1f')}) | {delta(e.get('DeltaW'), e.get('DeltaWCI95'), '.1f')} "
                     f"| {f(e['EffMHz'], '.0f')} | {delta(e.get('DeltaEffMHz'), e.get('DeltaEffCI95'), '.0f')} "
                     f"| {f(e['TempMaxC'], '.1f')}{' (thermal limit)' if e['ThermalLimit'] else ''} "
                     f"| {f(e['VcoreV'], '.3f')} | {f(e['JobsPerSecond'], '.0f')} "
                     f"| {e.get('Verdict', 'baseline')} |")
    return "\n".join(lines)


def load_rows(path):
    with Path(path).open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for key, convert in NUMERIC.items():
            if key in row:
                row[key] = convert(row[key]) if row[key] not in ("", None) else None
    return rows


def comma_values(value, convert=str):
    return [convert(v.strip()) for v in value.split(",") if v.strip()]


def repo_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", default="bin/x64-llvm-v3/ShaderStress.com",
                        help="comma-separated executables (repo-relative); the first is the "
                             "baseline, runs are interleaved in shuffled order")
    parser.add_argument("--label", default="adhoc", help="experiment id, e.g. P003-fadd-lane")
    parser.add_argument("--mode", choices=tuple(MODE_DEFAULTS), default="short",
                        help="short: steady all-compute A/B screening (default); "
                             "benchmark: the real 180 s benchmark for absolute numbers")
    parser.add_argument("--warmup", type=float, help="seconds before the window (8 / 30)")
    parser.add_argument("--measure", type=float, help="window length in seconds (15 / 148)")
    parser.add_argument("--repeats", type=int, help="interleaved rounds (5 / 3)")
    parser.add_argument("--preheat", type=int, help="unrecorded load before round 1 (30 / 0 s)")
    parser.add_argument("--threads", type=int, default=0, help="0 = all logical CPUs")
    parser.add_argument("--sample-interval", type=float, default=1.0,
                        help="PowerReader window in seconds (binaries before streaming: 6.5)")
    parser.add_argument("--max-gap", type=float, default=3.0,
                        help="largest tolerated gap between readings in seconds")
    parser.add_argument("--isas", default=None,
                        help=f"default {TARGET_ISAS} ({SWEEP_ISAS} with --sweep)")
    parser.add_argument("--sweep", action="store_true")
    parser.add_argument("--targets", default="win-v3,zig-v3,msvc")
    parser.add_argument("--buffers", default="64,128,256,512")
    parser.add_argument("--rounds", default="2,4,8")
    parser.add_argument("--seed", type=int, default=42, help="reproducible candidate order")
    parser.add_argument("--csv", default=None, help="default: <session>/results.csv")
    parser.add_argument("--max-background-load", type=float, default=10.0,
                        help="max system CPU %% before each run")
    parser.add_argument("--temp-limit", type=float, default=90.0,
                        help="CPU max temperature (C); runs within 1 C are flagged")
    parser.add_argument("--no-elevate", action="store_true", help="fail instead of using UAC")
    parser.add_argument("--snapshot", metavar="LABEL",
                        help="copy --snapshot-source to audit/power-baselines/LABEL and exit")
    parser.add_argument("--snapshot-source", default="bin/x64-llvm-v3")
    parser.add_argument("--summarize", metavar="CSV", help="print the summary of a results CSV")
    parser.add_argument("--baseline",
                        help="candidate the +/- deltas refer to (default: first --exe)")
    parser.add_argument(power_host.ELEVATED_FLAG, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--relay-log", help=argparse.SUPPRESS)
    parser.add_argument("--stop-file", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    for key, value in MODE_DEFAULTS[args.mode].items():
        if getattr(args, key) is None:
            setattr(args, key, value)
    if args.warmup < 3 or args.measure < 5:
        parser.error("warmup must be >= 3 s and the measurement window >= 5 s")
    if args.mode == "benchmark" and args.warmup + args.measure > BENCHMARK_SECONDS - 1:
        parser.error(f"benchmark runs {BENCHMARK_SECONDS} s: warmup + measure must be <= "
                     f"{BENCHMARK_SECONDS - 1}")
    if args.threads < 0 or args.repeats < 1 or args.preheat < 0:
        parser.error("threads must be >= 0 (0 = all), repeats positive, preheat >= 0")
    if not (0 < args.sample_interval <= args.max_gap):
        parser.error("need 0 < --sample-interval <= --max-gap")
    args.isas = comma_values(args.isas or (SWEEP_ISAS if args.sweep else TARGET_ISAS))
    if not args.isas or any(i not in ("scalar", "scalar-sim", "avx2", "avx512") for i in args.isas):
        parser.error("invalid ISA list")
    args.exe = [repo_path(e) for e in comma_values(args.exe)]
    labels = [e.parent.name for e in args.exe]
    if not args.exe or len(set(labels)) != len(labels):
        parser.error("--exe needs distinct parent directory names (they label the results)")
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
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.label):
        parser.error("--label: letters, digits, '.', '_', '-' (max 64)")
    args.csv = repo_path(args.csv) if args.csv else None
    return args


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_session(options, argv):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if options.baseline and options.baseline not in [Path(e).parent.name for e in options.exe]:
        raise RuntimeError(f"--baseline {options.baseline!r} is not one of the --exe candidates: " +
                           ", ".join(Path(e).parent.name for e in options.exe))
    session = make_evidence_dir(EVIDENCE, f"{options.label}-")
    csv_path = options.csv or session / "results.csv"
    if csv_path.exists():
        raise RuntimeError(f"refusing to replace existing results: {csv_path}; choose --csv")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    meta = {"Label": options.label, "Arguments": argv, "Started": stamp,
            "Mode": options.mode, "Warmup": options.warmup, "Measure": options.measure,
            "Repeats": options.repeats, "Preheat": options.preheat,
            "GitHead": (git("rev-parse", "HEAD") or "").strip() or None,
            "GitDirty": bool((git("status", "--porcelain") or "").strip()),
            "Processor": platform.processor(), "LogicalCpus": os.cpu_count(),
            "Python": sys.version.split()[0]}
    (session / "session.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    threads = options.threads or f"all ({os.cpu_count()})"
    seconds = run_seconds(options.mode, options.warmup, options.measure)
    print(f"Manual full CPU load: {threads} threads, {options.mode} mode, {seconds} s/run "
          f"(warmup {options.warmup} s, window {options.measure} s), {options.repeats} repeats, "
          f"ISAs {','.join(options.isas)}. Evidence: {session}", flush=True)
    if options.sweep:
        from scripts.build_options import select_configs  # configuration only, no toolchains
        configs = select_configs(comma_values(options.targets))
        if any(not c[3] for c in configs):
            raise RuntimeError("power sweep targets must be Windows builds")
        candidates = list(itertools.product(configs, options.buffers, options.rounds))
        random.Random(options.seed).shuffle(candidates)
    else:
        candidates = [(exe, None, None) for exe in options.exe]
    stop_file = Path(options.stop_file) if options.stop_file else None
    rows, stopped = [], False
    if options.preheat:
        power_host.wait_for_quiet_system(options.max_background_load)
        preheat(options.exe[0], options, session)
    # Every repeat visits all candidates in a newly shuffled order so drift
    # (temperature, background) hits all of them alike. Tuning binaries are
    # isolated and rebuilt as necessary; release outputs stay intact.
    for repeat in range(1, options.repeats + 1):
        order = list(candidates)
        random.Random(options.seed + repeat).shuffle(order)
        for candidate, buf, rounds in order:
            exe = candidate
            if buf is not None:
                target = candidate[1].removeprefix("bin/")
                env = dict(os.environ)
                env["SHADERSTRESS_EXTRA_DEFINES"] = f"-DSYNTH_BUF_KIB={buf} -DSYNTH_ROUNDS={rounds}"
                build_log = session / f"build-{target}-{buf}-{rounds}-{repeat}.log"
                with build_log.open("wb") as out:
                    result = subprocess.run([sys.executable, str(ROOT / "build.py"), target],
                                            cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise RuntimeError(f"build failed; evidence: {build_log}")
                exe = ROOT / (candidate[1] + "-tuning") / "ShaderStress.com"
            for isa in options.isas:
                if stop_file and stop_file.exists():
                    stopped = True
                    break
                load = power_host.wait_for_quiet_system(options.max_background_load)
                print(f"Measuring {exe.parent.name}: {isa}, buffer={buf}, rounds={rounds}, "
                      f"repeat={repeat} (background load {load}%)", flush=True)
                row = {"Label": options.label, "Build": exe.parent.name, "BufKiB": buf,
                       "Rounds": rounds, "Repeat": repeat, "BackgroundLoadPct": load,
                       **measure(exe, options, isa, session, exe.parent.name, repeat)}
                rows.append(row)
                write_rows(csv_path, rows)  # each completed run survives later failures
                print(f"  {row['Watts']} W (SD {row['StdDevW']} W, {row['Samples']} samples), "
                      f"eff {row['EffMHz']} MHz, Tmax {row['TempMaxC']} C, "
                      f"Vcore {row['VcoreV']} V", flush=True)
            if stopped:
                break
        if stopped:
            print("Stop requested; ending the session early.", flush=True)
            break
    (session / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    if rows:
        baseline = options.baseline or candidate_name(rows[0])
        summary = format_summary(summarize_runs(rows, baseline, temp_limit=options.temp_limit))
        (session / "summary.md").write_text(summary + "\n", encoding="utf-8")
        print("\n" + summary)
    print(f"Results: {csv_path}\nEvidence: {session}")
    return 130 if stopped else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    options = parse_args(argv)
    if options.relay_log:
        # Elevated child: the parent console relays this file.
        log = open(options.relay_log, "w", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
    if options.snapshot:
        dest = snapshot(options.snapshot, repo_path(options.snapshot_source))
        print(f"Snapshot: {dest}\nUse: --exe {dest.relative_to(ROOT).as_posix()}/ShaderStress.com,...")
        return 0
    if options.summarize:
        entries = summarize_runs(load_rows(repo_path(options.summarize)), options.baseline,
                                 options.temp_limit)
        print(format_summary(entries))
        return 0
    if sys.platform != "win32":
        raise RuntimeError("package power sampling currently requires Windows")
    if not options.sweep:
        missing = [str(e) for e in options.exe if not e.exists()]
        if missing:
            raise RuntimeError("executable not found: " + ", ".join(missing))
    if not power_host.is_admin():
        if options.no_elevate or options.elevated_child:
            raise RuntimeError("sensor readout needs an elevated process (omit --no-elevate "
                               "to request UAC elevation)")
        return power_host.relaunch_elevated(Path(__file__).resolve(), argv, EVIDENCE, ROOT)
    return run_session(options, argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
