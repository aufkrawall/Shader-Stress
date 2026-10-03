// PowerMeasure.cpp - CPU package power sampling via PowerReader.exe (LHM helper)
// PowerReader.exe is compiled at build time from vendor/lhm/PowerReader.cs.
// It loads LibreHardwareMonitorLib.dll, reads package power, average effective
// clock, temperature and core voltage via PawnIO, and prints them on one line.
// Requires admin privileges.
#include "core/Common.h"

namespace {
// Locale-independent decimal parser ("-1", "141.3"); the whole token must be
// consumed, so a decimal-comma reading ("121,3") is rejected, not truncated.
bool ParseDecimalToken(const char *&p, double &out) {
  bool negative = *p == '-';
  if (negative) ++p;
  // Exact integer mantissa / exact power of ten = one correctly rounded division.
  uint64_t mantissa = 0, divisor = 1;
  int digits = 0;
  for (; *p >= '0' && *p <= '9'; ++p, ++digits)
    if (digits < 15) mantissa = mantissa * 10 + (uint64_t)(*p - '0');
  if (*p == '.') {
    ++p;
    for (; *p >= '0' && *p <= '9'; ++p, ++digits) {
      if (digits >= 15) continue;
      mantissa = mantissa * 10 + (uint64_t)(*p - '0');
      divisor *= 10;
    }
  }
  bool endOfToken = *p == 0 || *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n';
  if (digits == 0 || digits > 15 || !endOfToken) return false;
  double value = (double)mantissa / (double)divisor;
  out = negative ? -value : value;
  return true;
}

void AppendFixed(std::wostringstream &o, const wchar_t *key, double v, int precision) {
  o << key << std::fixed << std::setprecision(precision) << (v > 0 ? v : -1.0);
}

bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
} // namespace

bool ParsePowerReaderOutput(const char *text, CpuPowerSample &out) {
  if (!text) return false;
  const char *p = text;
  double fields[4] = {-1, -1, -1, -1};
  int count = 0;
  for (;;) {
    while (IsSpace(*p)) ++p;
    if (*p == 0) break;
    if (count == 4 || !ParseDecimalToken(p, fields[count])) return false; // unknown format
    ++count;
  }
  if (count == 0 || !(fields[0] > 0 && fields[0] < 1000)) return false;
  out.watts = fields[0];
  out.effMhz = fields[1] > 0 && fields[1] < 20000 ? fields[1] : -1.0;
  out.tempC = fields[2] > 0 && fields[2] < 150 ? fields[2] : -1.0;
  out.vcore = fields[3] > 0 && fields[3] < 3 ? fields[3] : -1.0;
  return true;
}

std::wstring FormatPowerSampleLog(const CpuPowerSample &s, uint64_t elapsedMs, uint64_t jobs) {
  std::wostringstream o;
  o.imbue(std::locale::classic());
  o << L"Power sample: elapsed_ms=" << elapsedMs;
  AppendFixed(o, L" watts=", s.watts, 1);
  o << L" jobs=" << jobs;
  AppendFixed(o, L" eff_mhz=", s.effMhz, 0);
  AppendFixed(o, L" temp_c=", s.tempC, 1);
  AppendFixed(o, L" vcore_v=", s.vcore, 3);
  return o.str();
}

std::wstring FormatPowerReadout(const CpuPowerSample &s) {
  if (s.watts <= 0) return {};
  std::wstring r = std::to_wstring((int)(s.watts + 0.5)) + L" W";
  if (s.effMhz > 0) r += L" | eff " + std::to_wstring((int)(s.effMhz + 0.5)) + L" MHz";
  if (s.tempC > 0) r += L" | " + std::to_wstring((int)(s.tempC + 0.5)) + L" C";
  return r;
}

#if defined(_WIN32)
namespace {
std::mutex g_powerMutex;
CpuPowerSample g_cachedPower;
void PublishPower(CpuPowerSample sample) {
  std::lock_guard<std::mutex> lock(g_powerMutex);
  if (sample.watts > 0) {
    sample.tick = GetTick();
    g_cachedPower = sample;
  } else {
    g_cachedPower = CpuPowerSample{};
  }
}
HANDLE g_stopEvent = NULL; // manual-reset; signaled on shutdown
std::thread g_powerThread;

// Waits for `h` or the stop event. Returns true if `h` signaled.
bool WaitOrStop(HANDLE h, DWORD ms) {
  HANDLE hs[2] = {h, g_stopEvent};
  return WaitForMultipleObjects(2, hs, FALSE, ms) == WAIT_OBJECT_0;
}
wchar_t g_readerExe[MAX_PATH] = {};

bool IsPawnIOInstalled() {
  HKEY hKey = NULL;
  bool installed = false;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PawnIO", 0,
                    KEY_READ, &hKey) == ERROR_SUCCESS) {
    wchar_t ver[64] = {};
    DWORD verSize = sizeof(ver) - sizeof(wchar_t);
    if (RegQueryValueExW(hKey, L"DisplayVersion", NULL, NULL, (LPBYTE)ver, &verSize) ==
        ERROR_SUCCESS) {
      installed = wcslen(ver) > 0;
    }
    RegCloseKey(hKey);
  }
  return installed;
}

bool InstallPawnIO() {
  wchar_t setupPath[MAX_PATH];
  GetModuleFileNameW(NULL, setupPath, MAX_PATH);
  wchar_t *lastSlash = wcsrchr(setupPath, L'\\');
  if (!lastSlash) return false;
  wcscpy(lastSlash + 1, L"lhm\\PawnIO_setup.exe");

  if (GetFileAttributesW(setupPath) == INVALID_FILE_ATTRIBUTES) {
    g_App.Log(L"Power: PawnIO_setup.exe not found in lhm/");
    return false;
  }

  g_App.Log(L"Power: installing PawnIO driver...");
  SHELLEXECUTEINFOW sei = {sizeof(sei)};
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  sei.lpFile = setupPath;
  sei.lpParameters = L"-install -silent";
  sei.nShow = SW_HIDE;
  if (!ShellExecuteExW(&sei) || !sei.hProcess) {
    g_App.Log(L"Power: PawnIO install failed to start (error " +
              std::to_wstring(GetLastError()) + L")");
    return false;
  }
  if (!WaitOrStop(sei.hProcess, 30000))
    g_App.Log(L"Power: stopped waiting for the PawnIO installer");
  CloseHandle(sei.hProcess);

  if (IsPawnIOInstalled()) {
    g_App.Log(L"Power: PawnIO installed successfully");
    return true;
  }
  g_App.Log(L"Power: PawnIO installation failed");
  return false;
}

CpuPowerSample RunPowerReader() {
  wchar_t lhmDir[MAX_PATH];
  GetModuleFileNameW(NULL, lhmDir, MAX_PATH);
  wchar_t *lastSlash = wcsrchr(lhmDir, L'\\');
  if (!lastSlash) return {};
  wcscpy(lastSlash + 1, L"lhm");

  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  HANDLE hRead = NULL, hWrite = NULL;
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return {};
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = hWrite;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(g_readerExe, NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, lhmDir,
                      &si, &pi)) {
    CloseHandle(hRead);
    CloseHandle(hWrite);
    return {};
  }
  CloseHandle(hWrite);

  // A hung reader must not block this thread forever: kill it on timeout so
  // the pipe closes and ReadFile returns.
  if (!WaitOrStop(pi.hProcess, 8000)) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 2000);
  }
  // Read until EOF: the line is short, but a pipe read may return it in pieces.
  char buf[128] = {};
  DWORD totalRead = 0, n = 0;
  while (totalRead < sizeof(buf) - 1 &&
         ReadFile(hRead, buf + totalRead, sizeof(buf) - 1 - totalRead, &n, NULL) && n > 0)
    totalRead += n;
  CloseHandle(hRead);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  CpuPowerSample sample;
  if (totalRead == 0 || !ParsePowerReaderOutput(buf, sample)) return {};
  return sample;
}

void LogSensorAvailability(const CpuPowerSample &s) {
  std::wstring msg = L"Power: sensor OK (" + FormatPowerReadout(s) + L")";
  if (s.effMhz <= 0) msg += L"; effective clock sensor unavailable";
  if (s.tempC <= 0) msg += L"; temperature sensor unavailable";
  if (s.vcore <= 0) msg += L"; core voltage sensor unavailable";
  g_App.Log(msg);
}

void PowerThreadMain() {
  // Locate PowerReader.exe next to our binary
  GetModuleFileNameW(NULL, g_readerExe, MAX_PATH);
  wchar_t *lastSlash = wcsrchr(g_readerExe, L'\\');
  if (!lastSlash) return;
  wcscpy(lastSlash + 1, L"lhm\\PowerReader.exe");
  if (GetFileAttributesW(g_readerExe) == INVALID_FILE_ATTRIBUTES) {
    g_App.Log(L"Power: PowerReader.exe not found in lhm/ (power readout disabled)");
    return;
  }
  if (!IsPawnIOInstalled()) {
    g_App.Log(L"Power: PawnIO not installed, attempting auto-install...");
    if (!InstallPawnIO()) return;
  }
  g_App.Log(L"Power: testing sensor read...");
  CpuPowerSample test = RunPowerReader();
  if (test.watts <= 0) {
    g_App.Log(L"Power: sensor read failed (not admin, PawnIO not working or unparsable "
              L"PowerReader output)");
    return;
  }
  PublishPower(test);
  LogSensorAvailability(test);
  // Sample every 5 s until shutdown signals the stop event.
  bool failed = false;
  while (WaitForSingleObject(g_stopEvent, 5000) == WAIT_TIMEOUT) {
    CpuPowerSample sample = RunPowerReader();
    PublishPower(sample);
    if ((sample.watts <= 0) != failed) {
      failed = sample.watts <= 0;
      g_App.Log(failed ? L"Power: sensor read failed; cached sample invalidated"
                       : L"Power: sensor readings resumed");
    }
  }
}
} // namespace

void StartPowerMeasurement() {
  if (g_powerThread.joinable()) return;
  PublishPower(CpuPowerSample{});
  if (!g_stopEvent) g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent) return;
  ResetEvent(g_stopEvent);
  g_powerThread = std::thread(PowerThreadMain);
}

CpuPowerSample SampleCpuPower() {
  std::lock_guard<std::mutex> lock(g_powerMutex);
  if (g_cachedPower.tick == 0 || GetTick() - g_cachedPower.tick > 15000) return {};
  return g_cachedPower;
}
double SampleCpuPackagePower() { return SampleCpuPower().watts; }

void ShutdownPowerMeasurement() {
  if (g_stopEvent) SetEvent(g_stopEvent);
  if (g_powerThread.joinable()) g_powerThread.join();
}
#else
void StartPowerMeasurement() {}
CpuPowerSample SampleCpuPower() { return {}; }
double SampleCpuPackagePower() { return -1.0; }
void ShutdownPowerMeasurement() {}
#endif
