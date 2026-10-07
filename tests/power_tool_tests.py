"""Unit tests of the manual power measurement tooling (scripts/power_measure.py,
scripts/power_host.py). Called from run_tests.py; never starts a workload,
never requests UAC elevation."""
import contextlib
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import power_host  # noqa: E402
from scripts.power_measure import (binary_sha256, format_summary, load_rows, main,  # noqa: E402
                                   make_evidence_dir, measure, parse_args, planned_load_seconds, preheat,
                                   run_seconds, snapshot, summarize_runs,
                                   summarize_samples, verdict, workload_args, write_rows)

# Must equal the line asserted by TestPowerReaderFormat in src/app/SelfTest.cpp.
SELF_TEST_LINE = ("Power sample: elapsed_ms=31000 watts=141.3 jobs=42 eff_mhz=4425 "
                  "temp_c=81.3 vcore_v=1.194")


def sample(tick, watts, jobs, extra=""):
    return f"[23:59:59.000] Power sample: elapsed_ms={tick} watts={watts} jobs={jobs}{extra}"


def rejects(fn, *args):
    try:
        fn(*args)
    except (ValueError, RuntimeError):
        return True
    return False


def stream(ticks, watts=lambda t: 140.0, extra=""):
    """1 s PowerReader stream as logged by the watchdog."""
    return [sample(t, watts(t), t // 100, extra) for t in ticks]


def test_samples(check):
    # Short mode: 8 s warmup, 15 s window -> readings at 9..23 s (each covers the
    # second before its timestamp). Earlier/later readings and summaries are ignored.
    lines = stream(range(1000, 26000, 1000), lambda t: 130.0 if t < 9000 else 140.0 + (t // 1000) % 3)
    log = "\n".join(lines + ["[00:00:01.000] Final CPU Package Power: 900 W", "CPU Power: 900 W"])
    r = summarize_samples(log, 8, 15)
    check(r["Samples"] == 15 and r["Watts"] == 141.0 and r["FirstSampleMs"] == 9000 and
          r["LastSampleMs"] == 23000 and r["JobsPerSecond"] == 10 and r["EffMHz"] is None,
          "short window: readings of 9..23 s after 8 s warmup, warmup/summary lines excluded", str(r))
    window = [line for line in lines if 9000 <= int(line.split("elapsed_ms=")[1].split()[0]) <= 23000]
    gappy = [line for line in window if "elapsed_ms=15000" not in line and "elapsed_ms=16000" not in line
             and "elapsed_ms=17000" not in line]
    sparse = window[::2]
    for label, text, code in (("failed workload", log, 5), ("missing samples", "", 0),
                              ("duplicate reading", log + "\n" + lines[-1], 0),
                              ("a 4 s sensor outage", "\n".join(gappy), 0),
                              ("too few readings (old 6.5 s cadence)", "\n".join(sparse), 0),
                              ("no completed work", "\n".join(sample(t, 140, 1) for t in range(9000, 24000, 1000)), 0)):
        check(rejects(summarize_samples, text, 8, 15, code), "power measurement rejects " + label)
    legacy = [sample(t * 1000, w, t) for t, w in ((30, 120.2), (36, 122.4), (42, 124.6), (48, 122.4), (54, 120.2), (60, 121.0))]
    old = summarize_samples("\n".join(legacy), 30, 30, 0, 6.0, 15.0)
    check(old["Samples"] == 5 and old["Watts"] == 122.12,
          "binaries before streaming: --sample-interval 6 --max-gap 15 still measurable", str(old))

    sensors = stream(range(9000, 24000, 1000), extra=" eff_mhz=4400 temp_c=84.9 vcore_v=1.200")
    sensors[3] = sample(12000, 140.0, 120, " eff_mhz=-1 temp_c=-1.0 vcore_v=-1.000")
    sensors[4] = sample(13000, 140.0, 130, " eff_mhz=4386 temp_c=86.0 vcore_v=1.186")
    r = summarize_samples("\n".join(sensors), 8, 15)
    check(r["Samples"] == 15 and r["EffMHz"] == 4399 and r["TempMaxC"] == 86.0 and
          r["TempMeanC"] == 85.0 and r["VcoreV"] == 1.199,
          "effective clock / temperature / Vcore averaged; -1 readings treated as unavailable", str(r))
    contract = ["[00:00:31.000] " + SELF_TEST_LINE.replace("elapsed_ms=31000", f"elapsed_ms={t}")
                .replace("jobs=42", f"jobs={t}") for t in range(31000, 46000, 1000)]
    check(summarize_samples("\n".join(contract), 30, 15)["EffMHz"] == 4425,
          "self-test log line contract parses (SelfTest.cpp TestPowerReaderFormat)")


def test_arguments(check):
    args = workload_args("short", 23, "avx2", 0)
    check(args[:4] == ["--mode", "steady", "--duration", "23"] and "--threads" not in args and
          all(x in args for x in ("--no-ram", "--no-io", "--no-decompress")),
          "short mode: steady all-compute on all logical CPUs (benchmark worker layout)")
    check("--duration" not in workload_args("benchmark", 23, "avx2", 0) and
          workload_args("short", 23, "scalar", 16)[-6:-4] == ["--threads", "16"],
          "benchmark power window uses dedicated limit; explicit thread count is passed through")
    d = parse_args([])
    check((d.mode, d.warmup, d.measure, d.repeats, d.preheat) == ("benchmark", 8, 15, 5, 0) and
          run_seconds(d.mode, d.warmup, d.measure) == 23 and d.threads == 0 and
          d.isas == ["scalar-sim"] and
          d.exe == [PROJECT_ROOT / "bin/x64-llvm-v3/ShaderStress.com"] and d.csv is None,
          "defaults: benchmark job mix, compute only, 8+15 s, five scalar-sim runs (conclusive)")
    b = parse_args(["--mode", "benchmark"])
    check((b.warmup, b.measure, b.repeats, b.preheat) == (8, 15, 5, 0) and
          run_seconds(b.mode, b.warmup, b.measure) == 23,
          "benchmark power windows stop after 8 s warmup + 15 s measurement")
    check(workload_args(d.mode, 23, "avx2", 16) ==
          ["--mode", "benchmark", "--power-window", "23", "--isa", "avx2", "--threads", "16",
           "--no-ram", "--no-io", "--no-decompress", "--quiet"],
          "default launch uses benchmark job mix and only 16 compiler-sim compute threads")
    legacy = parse_args(["--mode", "short"])
    check((legacy.warmup, legacy.measure, legacy.repeats, legacy.preheat) == (8, 15, 5, 0) and
          legacy.isas == ["scalar-sim", "scalar", "avx2"],
          "explicit legacy steady mode remains available with bounded duration and no preheat")
    check(parse_args(["--sweep"]).isas == ["scalar", "avx2"], "sweep default skips the realistic sim")
    ab = parse_args(["--exe", "audit/power-baselines/P1-base/ShaderStress.com,bin/x64-llvm-v3/ShaderStress.com"])
    check([e.parent.name for e in ab.exe] == ["P1-base", "x64-llvm-v3"] and ab.exe[0].is_absolute(),
          "A/B executables are labelled by their directory")
    check(planned_load_seconds(d) == 115 and planned_load_seconds(ab) == 230 and
          planned_load_seconds(parse_args(["--isas", "scalar-sim,scalar,avx2",
                                          "--repeats", "3"])) == 207,
          "load planning accounts for executables, ISAs, repeats and bounded duration")
    check(planned_load_seconds(parse_args(["--sweep", "--targets", "win-v3", "--buffers", "128,512",
                                          "--rounds", "1", "--isas", "avx2"])) == 230,
          "sweep load planning counts each target/buffer/round candidate")
    with mock.patch("scripts.power_measure.sys.platform", "win32"), \
         mock.patch("scripts.power_measure.Path.exists", return_value=True), \
         mock.patch.object(power_host, "is_admin", return_value=False), \
         mock.patch.object(power_host, "relaunch_elevated", return_value=123) as relaunch:
        rc = main(["--exe", "audit/base/ShaderStress.com,audit/cand/ShaderStress.com",
                   "--isas", "scalar-sim,scalar,avx2", "--repeats", "30", "--allow-long-session"])
    check(rc == 123 and relaunch.called,
          "an explicitly allowed long session plans and reaches elevation")
    with mock.patch("scripts.power_measure.sys.platform", "win32"), \
         mock.patch("scripts.power_measure.Path.exists", return_value=True), \
         mock.patch.object(power_host, "is_admin", return_value=False), \
         mock.patch.object(power_host, "relaunch_elevated", return_value=123) as relaunch:
        long_refused = rejects(main, ["--exe", "audit/b/ShaderStress.com,audit/c1/ShaderStress.com,"
                                      "audit/c2/ShaderStress.com,audit/c3/ShaderStress.com"])
        three_ok = main(["--exe", "audit/b/ShaderStress.com,audit/c1/ShaderStress.com,"
                         "audit/c2/ShaderStress.com"]) == 123
    check(long_refused and three_ok,
          "session cap: 5 runs of baseline + 2 candidates allowed, 4 binaries refused before UAC")
    heat = parse_args(["--preheat", "23"])
    with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
         mock.patch("scripts.power_measure.run_workload", return_value=(0, "", None)) as launch:
        preheat(d.exe[0], heat, Path(tmp))
    check(planned_load_seconds(heat) == 138 and launch.call_args.args[1:5] ==
          ("benchmark", 23, "scalar-sim", 0),
          "benchmark preheat retains benchmark job mix and obeys the 23 s per-run cap")
    with contextlib.redirect_stderr(io.StringIO()):
        for invalid in (["--duration", "60"], ["--mode", "steady"], ["--warmup", "2"],
                        ["--measure", "4"], ["--mode", "benchmark", "--measure", "150"],
                        ["--warmup", "9"], ["--measure", "16"], ["--preheat", "24"],
                        ["--buffers", "31"], ["--rounds", "0"], ["--threads", "-1"],
                        ["--max-load-seconds", "600"],
                        ["--sample-interval", "5"], ["--isas", "sse9"],
                        ["--exe", "a/x/ShaderStress.com,b/x/ShaderStress.com"], ["--label", "../x"]):
            try:
                parse_args(invalid)
                rejected = False
            except SystemExit as error:
                rejected = error.code == 2
            check(rejected, "measurement rejects invalid arguments " + " ".join(invalid))


def runs(build, isa, watts, effs):
    return [{"Label": "t", "Build": build, "BufKiB": None, "Rounds": None, "Repeat": i + 1,
             "ISA": isa, "Watts": w, "EffMHz": e, "TempMaxC": 80.0, "VcoreV": 1.2,
             "JobsPerSecond": 100.0} for i, (w, e) in enumerate(zip(watts, effs))]


def test_summary(check, tmp):
    base = runs("base", "avx2", [120.0, 121.0, 122.0], [4500, 4510, 4490])
    better = runs("cand", "avx2", [125.1, 126.0, 126.9], [4450, 4460, 4440])
    noise = runs("noisy", "avx2", [119.0, 123.5, 121.0], [4500, 4505, 4495])
    tie = runs("tie", "avx2", [120.2, 121.1, 122.1], [4440, 4452, 4428])
    entries = summarize_runs(base + better + noise + tie)
    by = {e["Candidate"]: e for e in entries}
    check(by["base"].get("Verdict") is None and by["cand"]["DeltaW"] == 5.0 and
          by["cand"]["Pairs"] == 3 and by["cand"]["Verdict"].startswith("better") and
          by["cand"]["DeltaEffMHz"] == -50,
          "summary: paired per-repeat deltas vs the first candidate", str(by["cand"]))
    check(by["noisy"]["Verdict"].startswith("inconclusive") and by["tie"]["Verdict"].startswith("tie-break better"),
          "summary: noise is inconclusive; equal power with lower effective clock wins the tie",
          f"{by['noisy']} {by['tie']}")
    check(verdict(-3.0, 1.0, 0, 5) == "worse (less power)" and
          verdict(0.8, 0.1, None, None).startswith("inconclusive") and
          verdict(5.0, None, None, None).startswith("inconclusive (needs"),
          "verdict: power loss is worse; < 1 W never decides; one repeat is not enough")
    hot = summarize_runs(runs("hot", "scalar", [130.0, 131.0], [4300, 4310]), temp_limit=80.5)
    check(hot[0]["ThermalLimit"] and "(thermal limit)" in format_summary(hot),
          "summary flags runs at the temperature limit")
    table = format_summary(entries)
    check(table.count("\n") == len(entries) + 1 and "+5.0 +-" in table, "summary table renders", table)
    path = Path(tmp) / "results.csv"
    write_rows(path, base + better)
    again = summarize_runs(load_rows(path))
    check([e.get("DeltaW") for e in again] == [None, 5.0], "summary of a saved CSV matches", str(again))
    swapped = {e["Candidate"]: e.get("DeltaW") for e in summarize_runs(base + better, "cand")}
    check(swapped == {"base": -5.0, "cand": None} and rejects(summarize_runs, base, "typo"),
          "summary baseline can be chosen; an unknown baseline is an error", str(swapped))


def test_snapshot(check, tmp):
    src = Path(tmp) / "x64-llvm-v3"
    (src / "lhm").mkdir(parents=True)
    (src / "ShaderStress.com").write_bytes(b"launcher")
    (src / "ShaderStress.exe").write_bytes(b"workload")
    (src / "lhm" / "PowerReader.exe").write_bytes(b"reader")
    (src / "ShaderStress.log").write_text("log", encoding="utf-8")
    dest = snapshot("P1-base", src, Path(tmp) / "baselines")
    meta = json.loads((dest / "SNAPSHOT.json").read_text(encoding="utf-8"))
    check((dest / "lhm" / "PowerReader.exe").exists() and not (dest / "ShaderStress.log").exists() and
          meta["SHA256"] == hashlib.sha256(b"workload").hexdigest() and meta["Label"] == "P1-base" and
          "GitDirty" in meta and (not meta["GitDirty"] or (dest / "changes.patch").exists()),
          "snapshot copies the build (incl. lhm/), hashes the workload exe, records git state", str(meta))
    check(rejects(snapshot, "P1-base", src, Path(tmp) / "baselines") and
          rejects(snapshot, "../evil", src, Path(tmp) / "baselines"),
          "snapshot refuses to overwrite or escape its directory")
    check(binary_sha256(src / "ShaderStress.com") == hashlib.sha256(b"workload").hexdigest(),
          "recorded SHA-256 identifies ShaderStress.exe, not the CLI launcher")
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            parse_args(["--baseline", "P1-base"])
            explicit_ok = True
        except SystemExit:
            explicit_ok = False
    check(explicit_ok, "session baseline can name any --exe candidate up front")


def test_evidence_dirs(check, tmp):
    # Regression: tempfile.mkdtemp() applies 0o700, which Windows maps to an
    # owner-only DACL. A session created by the elevated child then locked
    # out the unelevated shell (results.csv unreadable, summary unrecoverable).
    parent = Path(tmp) / "evidence"
    parent.mkdir()
    first = make_evidence_dir(parent, "P1-")
    check(first.is_dir() and first.parent == parent,
          "evidence dir is created inside the given parent", str(first))
    second = make_evidence_dir(parent, "P1-")
    check(second != first and second.is_dir(),
          "a second evidence dir gets a fresh non-colliding name", str(second))
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        owner = wintypes.HANDLE()
        check(advapi.GetNamedSecurityInfoW(str(first), 1, 1, None, None, None, None,
                                           ctypes.byref(owner)) != 0 or owner.value is not None,
              "evidence dir carries an owner SID (no broken security descriptor)")


def test_host(check, tmp):
    params = power_host.child_arguments(Path("C:/a b/power_measure.py"), ["--label", "x y"],
                                        Path("C:/l o/g.log"), Path("C:/s.stop"))
    check('"C:\\a b\\power_measure.py"' in params.replace("/", "\\") and '"x y"' in params and
          power_host.ELEVATED_FLAG in params.split() and "--relay-log" in params,
          "elevated child gets the same arguments plus relay/stop paths (quoted)", params)
    log = Path(tmp) / "relay.log"
    out = io.StringIO()
    relay = power_host.LogRelay(log, out)
    relay.pump()
    data = "Messung 1: 140 W \u00b0C\n".encode("utf-8")
    log.write_bytes(data[:-3])  # split inside the UTF-8 sequence of the degree sign
    relay.pump()
    log.write_bytes(data)
    relay.pump(final=True)
    check(out.getvalue() == data.decode("utf-8"), "relay forwards growing log, split UTF-8 intact",
          repr(out.getvalue()))
    check(power_host.busy_percent((0, 0, 0), (900, 1000, 0)) == 10.0 and
          power_host.busy_percent((5, 5, 5), (5, 5, 5)) == 0.0,
          "background load from idle/kernel/user deltas")
    readings = iter([(0, 0, 0), (500, 1000, 0), (500, 1000, 0), (1450, 2000, 0)])
    load = power_host.wait_for_quiet_system(10.0, window=0, attempts=2,
                                            times=lambda: next(readings), sleep=lambda s: None)
    busy = iter([(0, 0, 0), (100, 1000, 0)] * 3)
    check(load == 5.0 and rejects(power_host.wait_for_quiet_system, 10.0, 0, 3,
                                  lambda: next(busy), lambda s: None),
          "quiet-system check waits for an idle window, refuses a busy system")
    if sys.platform == "win32":
        import ctypes
        check(ctypes.sizeof(power_host.SHELLEXECUTEINFOW) == (112 if sys.maxsize > 2**32 else 60),
              "SHELLEXECUTEINFOW layout matches the Windows SDK")


def test_foreign_load(check, tmp):
    # Regression: background bursts (up to 100% CPU) during a window used to go
    # unnoticed because only the idle time before each run was checked.
    check(power_host.foreign_percent((0, 0, 0), (100, 1000, 0), 0, 880) == 2.0 and
          power_host.foreign_percent((0, 0, 0), (0, 1000, 0), 0, 1000) == 0.0 and
          power_host.foreign_percent((0, 0, 0), (0, 0, 0), 0, 0) == 0.0 and
          power_host.foreign_percent((0, 0, 0), (0, 500, 500), 0, 0) == 100.0,
          "foreign CPU share = busy time minus the workload job's CPU time")
    d = parse_args([])
    check((d.max_foreign_load, d.foreign_retries, d.quiet_timeout) == (10.0, 4, 600.0),
          "default: windows with > 10% foreign CPU (3-4% interrupt floor + ~1 busy logical CPU) are repeated")
    log = "\n".join(stream(range(9000, 23001, 1000)))
    results = iter([(0, log, 19.5), (0, log, 4.4)])
    seen, waits = [], []

    def fake_run(exe, mode, seconds, isa, threads, run_dir, window):
        seen.append((run_dir, window))
        return next(results)
    with contextlib.redirect_stdout(io.StringIO()) as out, \
         mock.patch("scripts.power_measure.binary_sha256", return_value="x"):
        row = measure(Path(tmp) / "ShaderStress.com", d, "scalar-sim", tmp, "lbl", 1,
                      run=fake_run, quiet=waits.append)
    check(row["Attempts"] == 2 and row["ForeignCpuPct"] == 4.4 and len(seen) == 2 and
          seen[0][0] != seen[1][0] and seen[0][1] == (8, 23) and waits == [10.0] and
          row["Evidence"] == str(seen[1][0]) and "rejected: foreign CPU load 19.5%" in out.getvalue(),
          "a run with foreign load is kept as evidence, the system re-checked, the run repeated",
          str(row))
    busy = parse_args(["--foreign-retries", "1"])
    with contextlib.redirect_stdout(io.StringIO()):
        check(rejects(measure, Path(tmp) / "x.com", busy, "scalar", tmp, "busy", 1,
                      lambda *a: (0, log, 50.0), lambda m: None),
              "persistent foreign load fails the session instead of recording confounded data")
    with contextlib.redirect_stderr(io.StringIO()):
        for invalid in (["--max-foreign-load", "0"], ["--foreign-retries", "-1"],
                        ["--quiet-timeout", "1"]):
            try:
                parse_args(invalid)
                rejected = False
            except SystemExit as error:
                rejected = error.code == 2
            check(rejected, "rejects " + " ".join(invalid))
    with mock.patch.object(power_host, "wait_for_quiet_system", return_value=1.0) as wait:
        from scripts.power_measure import wait_quiet
        wait_quiet(d)
    check(wait.call_args.args == (10.0,) and wait.call_args.kwargs == {"attempts": 200},
          "quiet check waits up to --quiet-timeout (busy hosts are waited out, not fatal)")
    if sys.platform == "win32":
        # The job must account a grandchild (ShaderStress.com -> ShaderStress.exe).
        child = "s = 0\nfor i in range(2_000_000): s += i"
        parent = f"import subprocess, sys; sys.exit(subprocess.run([sys.executable, '-c', {child!r}]).returncode + 3)"
        with open(Path(tmp) / "tracked.log", "wb") as out:
            tracked = power_host.TrackedProcess([sys.executable, "-c", parent], tmp, out)
            try:
                code = tracked.proc.wait(timeout=60)
                cpu = tracked.cpu_time()
            finally:
                tracked.close()
        check(code == 3 and cpu > 500_000 and tracked.job is None,
              "job object accounts the CPU time of the launched process tree", f"{code} {cpu}")


def run_power_tool_tests(check):
    with tempfile.TemporaryDirectory() as tmp:
        test_samples(check)
        test_arguments(check)
        test_summary(check, tmp)
        test_snapshot(check, tmp)
        test_evidence_dirs(check, tmp)
        test_host(check, tmp)
        test_foreign_load(check, tmp)
