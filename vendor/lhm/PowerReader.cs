// PowerReader.exe — reads CPU Package Power via LibreHardwareMonitorLib
// Compiled at build time, launched from ShaderStress C++ via CreateProcess
// Output: one line "watts" (e.g. "84.2") or "-1" on failure

using System;
using System.IO;
using LibreHardwareMonitor.Hardware;

class Program {
    static int Main(string[] args) {
        try {
            // Locate DLL next to this exe
            string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string dllPath = Path.Combine(exeDir, "LibreHardwareMonitorLib.dll");
            if (!File.Exists(dllPath)) {
                Console.WriteLine("-1");
                return 1;
            }

            var computer = new Computer();
            computer.IsCpuEnabled = true;
            computer.Open();

            // Small delay for sensor initialization
            System.Threading.Thread.Sleep(200);

            double power = -1.0;
            foreach (var hw in computer.Hardware) {
                hw.Update();
                foreach (var sensor in hw.Sensors) {
                    if (sensor.SensorType == SensorType.Power &&
                        sensor.Name == "Package" &&
                        sensor.Value.HasValue &&
                        sensor.Value.Value > 0) {
                        power = sensor.Value.Value;
                    }
                }
            }

            computer.Close();
            Console.WriteLine(power.ToString("F1"));
            return 0;
        } catch (Exception ex) {
            Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
            Console.WriteLine("-1");
            return 1;
        }
    }
}
