// PowerReader.exe — reads CPU sensors via LibreHardwareMonitorLib
// Compiled at build time, launched from ShaderStress C++ via CreateProcess
// Output: one line "watts effMHz tempC vcoreV" (invariant culture), e.g.
// "141.3 4425 81.3 1.194". A sensor this CPU lacks prints -1; failure prints
// "-1 -1 -1 -1" with exit code 1. Parsed by ParsePowerReaderOutput().

using System;
using System.IO;
using System.Globalization;
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

    static int Main(string[] args) {
        try {
            // Locate DLL next to this exe
            string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string dllPath = Path.Combine(exeDir, "LibreHardwareMonitorLib.dll");
            if (!File.Exists(dllPath)) {
                Console.WriteLine("-1 -1 -1 -1");
                return 1;
            }

            var computer = new Computer();
            computer.IsCpuEnabled = true;
            computer.Open();

            // Package power (energy counter) and effective clocks (APERF/MPERF)
            // are deltas between two updates: prime once, then average over a
            // 1 s measurement window (not a synchronization delay).
            foreach (var hw in computer.Hardware) hw.Update();
            System.Threading.Thread.Sleep(1000);

            double power = -1.0, eff = -1.0, temp = -1.0, vcore = -1.0;
            double effSum = 0;
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

            computer.Close();
            Console.WriteLine(Fmt(power, "F1") + " " + Fmt(eff, "F0") + " " +
                              Fmt(temp, "F1") + " " + Fmt(vcore, "F3"));
            return power > 0 ? 0 : 1;
        } catch (Exception ex) {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            Console.WriteLine("-1 -1 -1 -1");
            return 1;
        }
    }
}
