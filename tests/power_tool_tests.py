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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import power_host  # noqa: E402
from scripts.power_measure import (binary_sha256, format_summary, load_rows,  # noqa: E402
                                   parse_args, snapshot, summarize_runs, summarize_samples,
                                   verdict, workload_args, write_rows)

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


def test_samples(check):
    lines = [sample(0, 20, 0), sample(10000, 30, 5)] + [
        sample(t * 1000, w, t) for t, w in ((30, 120.2), (36, 122.4), (42, 124.6), (48, 122.4), (54, 120.2))]
    log = "\n".join(lines + ["[00:00:01.000] Final CPU Package Power: 900 W", "CPU Power: 900 W"])
    result = summarize_samples(log, 30, 60)
    check(result["Samples"] == 5 and result["Watts"] == 121.96 and result["JobsPerSecond"] == 1
          and result["EffMHz"] is None and result["TempMaxC"] is None,
          "power warmup uses acquisition time; summaries excluded; old log format accepted")
    for label, text, code in (("failed workload", log, 5), ("missing samples", "", 0),
                              ("duplicate reading", log + "\n" + lines[-1], 0),
                              ("sensor outage", "\n".join(lines[:4] + [sample(58000, 120, 60)]), 0),
                              ("no completed work", "\n".join(sample(t, 120, 1) for t in (30000, 36000, 42000, 48000, 54000)), 0)):
        check(rejects(summarize_samples, text, 30, 60, code), "power measurement rejects " + label)

    def full(tick, watts, jobs, eff, temp, vcore):
        return sample(tick, watts, jobs, f" eff_mhz={eff} temp_c={temp} vcore_v={vcore}")
    contract = "[00:00:31.000] " + SELF_TEST_LINE
    sensors = "\n".join([contract.replace("elapsed_ms=31000", "elapsed_ms=30500"),
                         full(36000, 140.1, 50, 4400, 84.9, 1.2),
                         full(42000, 139.9, 60, -1, -1.0, -1.000),
                         full(48000, 140.7, 70, 4380, 86.0, 1.188)])
    r = summarize_samples(sensors, 30, 60)
    check(r["Samples"] == 4 and r["EffMHz"] == 4402 and r["TempMaxC"] == 86.0 and
          r["TempMeanC"] == 84.1 and r["VcoreV"] == 1.194,
          "effective clock / temperature / Vcore averaged; -1 readings treated as unavailable",
          str(r))
    check(summarize_samples("\n".join([contract] + [contract.replace("31000", str(t)).replace("jobs=42", f"jobs={t}")
                                                     for t in (40000, 50000)]), 30, 60)["EffMHz"] == 4425,
          "self-test log line contract parses (SelfTest.cpp TestPowerReaderFormat)")


def test_arguments(check):
    args = workload_args("benchmark", 180, "avx2", 0)
    check("--threads" not in args and all(x in args for x in ("--no-ram", "--no-io", "--no-decompress")),
          "measurement default: all logical CPUs (benchmark thread count), compute only")
    check(workload_args("steady", 60, "scalar", 16)[-6:-4] == ["--threads", "16"],
          "explicit thread count is passed through")
    d = parse_args([])
    check(d.duration == 180 and d.threads == 0 and d.isas == ["scalar-sim", "scalar", "avx2"] and
          d.exe == [PROJECT_ROOT / "bin/x64-llvm-v3/ShaderStress.com"] and d.csv is None,
          "defaults: 180 s benchmark, all target ISAs, repo-relative exe, CSV in session dir")
    check(parse_args(["--sweep"]).isas == ["scalar", "avx2"], "sweep default skips the realistic sim")
    ab = parse_args(["--exe", "audit/power-baselines/P1-base/ShaderStress.com,bin/x64-llvm-v3/ShaderStress.com"])
    check([e.parent.name for e in ab.exe] == ["P1-base", "x64-llvm-v3"] and ab.exe[0].is_absolute(),
          "A/B executables are labelled by their directory")
    with contextlib.redirect_stderr(io.StringIO()):
        for invalid in (["--duration", "60"], ["--buffers", "31"], ["--rounds", "0"],
                        ["--threads", "-1"], ["--warmup", "170"], ["--isas", "sse9"],
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


def run_power_tool_tests(check):
    with tempfile.TemporaryDirectory() as tmp:
        test_samples(check)
        test_arguments(check)
        test_summary(check, tmp)
        test_snapshot(check, tmp)
        test_host(check, tmp)
