// PowerReader.exe — reads CPU sensors via LibreHardwareMonitorLib
// Compiled at build time, launched from ShaderStress C++ via CreateProcess.
// Output lines: "watts effMHz tempC vcoreV" (invariant culture), e.g.
// "141.3 4425 81.3 1.194"; a sensor this CPU lacks prints -1. Parsed by
// ParsePowerReaderOutput().
//   PowerReader.exe                 one reading over a 1 s window, then exit
//   PowerReader.exe --stream <ms>   one reading per <ms> until stdin closes;
//                                   consecutive windows are contiguous
// Exit code 1 and "-1 -1 -1 -1" when package power is unavailable (not admin,
// PawnIO missing) on the first reading.

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using LibreHardwareMonitor.Hardware;

class Program {
    // First match wins (AMD Zen names first, then Intel/generic).
    static readonly string[] TempNames = { "Core (Tctl/Tdie)", "Core (Tctl)", "Core (Tdie)", "CPU Package", "Core Max" };
    static readonly string[] VcoreNames = { "Core (SVI2 TFN)", "CPU Core", "Vcore" };

    static int Rank(string[] names, string name) {
        int i = Array.IndexOf(names, name);
        return i < 0 ? int.MaxValue : i;
    }

    static string Fmt(double v, string format) {
        return v > 0 ? v.ToString(format, CultureInfo.InvariantCulture) : "-1";
    }

    // Package power (energy counter) and effective clocks (APERF/MPERF) are
    // deltas since the previous Update(), i.e. averages over the window.
    static double[] Read(Computer computer) {
        double power = -1.0, eff = -1.0, temp = -1.0, vcore = -1.0, effSum = 0;
        int effCount = 0, tempRank = int.MaxValue, vcoreRank = int.MaxValue;
        foreach (var hw in computer.Hardware) {
            if (hw.HardwareType != HardwareType.Cpu) continue;
            hw.Update();
            foreach (var sensor in hw.Sensors) {
                if (!sensor.Value.HasValue || !(sensor.Value.Value > 0)) continue;
                double v = sensor.Value.Value;
                string n = sensor.Name;
                if (sensor.SensorType == SensorType.Power && n == "Package") {
                    power = v;
                } else if (sensor.SensorType == SensorType.Clock) {
                    if (n == "Cores (Average Effective)") eff = v;
                    else if (n.EndsWith(" (Effective)")) { effSum += v; ++effCount; }
                } else if (sensor.SensorType == SensorType.Temperature && Rank(TempNames, n) < tempRank) {
                    tempRank = Rank(TempNames, n);
                    temp = v;
                } else if (sensor.SensorType == SensorType.Voltage && Rank(VcoreNames, n) < vcoreRank) {
                    vcoreRank = Rank(VcoreNames, n);
                    vcore = v;
                }
            }
            break; // first CPU package only
        }
        if (eff <= 0 && effCount > 0) eff = effSum / effCount;
        return new[] { power, eff, temp, vcore };
    }

    static void Print(double[] r) {
        Console.Out.WriteLine(Fmt(r[0], "F1") + " " + Fmt(r[1], "F0") + " " +
                              Fmt(r[2], "F1") + " " + Fmt(r[3], "F3"));
        Console.Out.Flush();
    }

    static int Main(string[] args) {
        int intervalMs = 0;
        if (args.Length > 0 && (args.Length != 2 || args[0] != "--stream" ||
                                !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out intervalMs) ||
                                intervalMs < 200 || intervalMs > 60000)) {
            Console.Error.WriteLine("usage: PowerReader.exe [--stream <200..60000 ms>]");
            return 2;
        }
        Computer computer = null;
        try {
            string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            if (!File.Exists(Path.Combine(exeDir, "LibreHardwareMonitorLib.dll"))) {
                Console.WriteLine("-1 -1 -1 -1");
                return 1;
            }
            computer = new Computer();
            computer.IsCpuEnabled = true;
            computer.Open();
            foreach (var hw in computer.Hardware) hw.Update(); // prime the delta counters

            // Stream mode stops when the parent closes stdin (or dies).
            var stop = new ManualResetEvent(false);
            if (intervalMs > 0) {
                var watcher = new Thread(() => {
                    try {
                        var stdin = Console.OpenStandardInput();
                        var b = new byte[64];
                        while (stdin.Read(b, 0, b.Length) > 0) { }
                    } catch (IOException) { }
                    stop.Set();
                });
                watcher.IsBackground = true;
                watcher.Start();
            }

            // The waits below are the measurement windows, not synchronization.
            int window = intervalMs > 0 ? intervalMs : 1000;
            var clock = Stopwatch.StartNew();
            long next = window;
            for (bool first = true; ; first = false) {
                long wait = next - clock.ElapsedMilliseconds;
                if (wait > 0 && stop.WaitOne((int)wait)) break;
                // Never burst after a stall: the next window starts now.
                next = Math.Max(next, clock.ElapsedMilliseconds) + window;
                double[] r = Read(computer);
                Print(r);
                if (first && !(r[0] > 0)) return 1; // sensor unavailable
                if (intervalMs == 0) break;
            }
            return 0;
        } catch (IOException) {
            return 0; // parent closed stdout: nothing left to report to
        } catch (Exception ex) {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            try { Console.WriteLine("-1 -1 -1 -1"); } catch (IOException) { }
            return 1;
        } finally {
            if (computer != null) computer.Close();
        }
    }
}
