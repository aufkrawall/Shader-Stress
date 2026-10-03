// PowerMeasure.cpp - CPU package power sampling via PowerReader.exe (LHM helper)
// PowerReader.exe is compiled at build time from vendor/lhm/PowerReader.cs.
// It loads LibreHardwareMonitorLib.dll and, in --stream mode, prints package
// power, average effective clock, temperature and core voltage once per
// second over contiguous windows (so averaging readings averages energy).
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

void PowerSampleQueue::Push(const CpuPowerSample &s) {
  std::lock_guard<std::mutex> lock(m_);
  if (q_.size() == kCapacity) {
    q_.pop_front();
    ++dropped_;
  }
  q_.push_back(s);
}

std::vector<CpuPowerSample> PowerSampleQueue::Drain() {
  std::lock_guard<std::mutex> lock(m_);
  std::vector<CpuPowerSample> out(q_.begin(), q_.end());
  q_.clear();
  return out;
}

uint64_t PowerSampleQueue::Dropped() {
  std::lock_guard<std::mutex> lock(m_);
  return dropped_;
}

#if defined(_WIN32)
namespace {
constexpr int kReaderIntervalMs = 1000; // contiguous measurement windows
std::mutex g_powerMutex;
CpuPowerSample g_cachedPower;
PowerSampleQueue g_sampleQueue; // every reading, for the watchdog's sample log
void PublishPower(CpuPowerSample sample) {
  std::lock_guard<std::mutex> lock(g_powerMutex);
  if (sample.watts > 0) {
    sample.tick = GetTick();
    g_cachedPower = sample;
    g_sampleQueue.Push(sample);
  } else {
    g_cachedPower = CpuPowerSample{};
  }
}
HANDLE g_stopEvent = NULL; // manual-reset; signaled on shutdown
std::thread g_powerThread;
// Running PowerReader instance. Shutdown closes its stdin (graceful EOF) and,
// if it hangs, terminates it so the power thread's blocking ReadFile returns.
std::mutex g_readerMutex;
HANDLE g_readerProcess = NULL, g_readerStdin = NULL;

// Waits for `h` or the stop event. Returns true if `h` signaled.
bool WaitOrStop(HANDLE h, DWORD ms) {
  HANDLE hs[2] = {h, g_stopEvent};
  return WaitForMultipleObjects(2, hs, FALSE, ms) == WAIT_OBJECT_0;
}
bool StopRequestedPower() { return WaitForSingleObject(g_stopEvent, 0) != WAIT_TIMEOUT; }
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

// Starts "PowerReader.exe --stream <ms>" with piped stdin/stdout. Returns the
// stdout read handle (NULL on failure or when shutdown already began).
HANDLE StartStreamingReader() {
  wchar_t lhmDir[MAX_PATH];
  wcscpy(lhmDir, g_readerExe);
  *wcsrchr(lhmDir, L'\\') = 0;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  HANDLE outRead = NULL, outWrite = NULL, inRead = NULL, inWrite = NULL;
  if (!CreatePipe(&outRead, &outWrite, &sa, 0)) return NULL;
  if (!CreatePipe(&inRead, &inWrite, &sa, 0)) {
    CloseHandle(outRead);
    CloseHandle(outWrite);
    return NULL;
  }
  SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(inWrite, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = inRead;
  si.hStdOutput = outWrite;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION pi = {};
  std::wstring cmd = L"PowerReader.exe --stream " + std::to_wstring(kReaderIntervalMs);
  std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
  cmdBuf.push_back(0);
  BOOL started = FALSE;
  DWORD error = 0;
  {
    std::lock_guard<std::mutex> lock(g_readerMutex);
    if (!StopRequestedPower()) {
      started = CreateProcessW(g_readerExe, cmdBuf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW,
                               NULL, lhmDir, &si, &pi);
      error = GetLastError();
      if (started) {
        g_readerProcess = pi.hProcess;
        g_readerStdin = inWrite;
        inWrite = NULL;
      }
    }
  }
  CloseHandle(outWrite);
  CloseHandle(inRead);
  if (inWrite) CloseHandle(inWrite);
  if (!started) {
    CloseHandle(outRead);
    if (error) g_App.Log(L"Power: could not start PowerReader.exe (error " +
                         std::to_wstring(error) + L")");
    return NULL;
  }
  CloseHandle(pi.hThread);
  return outRead;
}

// Closes the reader's stdin, waits briefly for it to exit (terminating a hung
// one) and returns its exit code.
DWORD ReleaseReader() {
  HANDLE process = NULL, in = NULL;
  {
    std::lock_guard<std::mutex> lock(g_readerMutex);
    std::swap(process, g_readerProcess);
    std::swap(in, g_readerStdin);
  }
  if (in) CloseHandle(in);
  DWORD code = (DWORD)-1;
  if (process) {
    if (WaitForSingleObject(process, 3000) == WAIT_TIMEOUT) {
      TerminateProcess(process, 1);
      WaitForSingleObject(process, 3000);
    }
    GetExitCodeProcess(process, &code);
    CloseHandle(process);
  }
  return code;
}

void LogSensorAvailability(const CpuPowerSample &s) {
  std::wstring msg = L"Power: sensor OK (" + FormatPowerReadout(s) + L")";
  if (s.effMhz <= 0) msg += L"; effective clock sensor unavailable";
  if (s.tempC <= 0) msg += L"; temperature sensor unavailable";
  if (s.vcore <= 0) msg += L"; core voltage sensor unavailable";
  g_App.Log(msg);
}

// Publishes every streamed line until the reader exits. Returns the number
// of valid readings.
uint64_t StreamReadings(HANDLE out) {
  std::string line;
  char buf[512];
  DWORD n = 0;
  uint64_t valid = 0;
  bool failed = false;
  while (ReadFile(out, buf, sizeof(buf), &n, NULL) && n > 0) {
    for (DWORD i = 0; i < n; ++i) {
      if (buf[i] != '\n') {
        if (line.size() < 256) line += buf[i]; // overlong lines fail to parse
        continue;
      }
      CpuPowerSample sample;
      const bool ok = ParsePowerReaderOutput(line.c_str(), sample);
      line.clear();
      PublishPower(ok ? sample : CpuPowerSample{});
      if (ok) {
        if (valid++ == 0) LogSensorAvailability(sample);
        else if (failed) g_App.Log(L"Power: sensor readings resumed");
        failed = false;
      } else if (valid > 0 && !failed) {
        failed = true;
        g_App.Log(L"Power: sensor read failed; cached sample invalidated");
      }
    }
  }
  return valid;
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
  g_App.Log(L"Power: starting sensor stream (" + std::to_wstring(kReaderIntervalMs) +
            L" ms windows)");
  uint64_t total = 0;
  int failedStarts = 0;
  while (!StopRequestedPower()) {
    HANDLE out = StartStreamingReader();
    if (!out) break;
    const uint64_t valid = StreamReadings(out);
    CloseHandle(out);
    const DWORD code = ReleaseReader();
    PublishPower(CpuPowerSample{});
    if (StopRequestedPower()) break;
    total += valid;
    if (total == 0) {
      g_App.Log(L"Power: sensor read failed (not admin, PawnIO not working or unparsable "
                L"PowerReader output; reader exit code " + std::to_wstring((long)code) +
                L"); power readout disabled");
      break;
    }
    failedStarts = valid ? 0 : failedStarts + 1;
    g_App.Log(L"Power: PowerReader exited (code " + std::to_wstring((long)code) + L") after " +
              std::to_wstring(valid) + L" readings");
    if (failedStarts >= 3) {
      g_App.Log(L"Power: reader keeps failing; power readout disabled");
      break;
    }
    // Back-off before restarting a reader that died mid-run.
    if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
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
  if (g_cachedPower.tick == 0 || GetTick() - g_cachedPower.tick > 5000) return {};
  return g_cachedPower;
}
double SampleCpuPackagePower() { return SampleCpuPower().watts; }

std::vector<CpuPowerSample> TakePowerSamples(uint64_t *dropped) {
  if (dropped) *dropped = g_sampleQueue.Dropped();
  return g_sampleQueue.Drain();
}

void ShutdownPowerMeasurement() {
  if (g_stopEvent) SetEvent(g_stopEvent);
  HANDLE process = NULL;
  {
    std::lock_guard<std::mutex> lock(g_readerMutex);
    if (g_readerStdin) {
      CloseHandle(g_readerStdin); // EOF: the reader exits on its own
      g_readerStdin = NULL;
    }
    if (g_readerProcess)
      DuplicateHandle(GetCurrentProcess(), g_readerProcess, GetCurrentProcess(), &process, 0,
                      FALSE, DUPLICATE_SAME_ACCESS);
  }
  if (process) {
    // Bounded: a hung reader must not block exit (its pipe closes on termination).
    if (WaitForSingleObject(process, 3000) == WAIT_TIMEOUT) TerminateProcess(process, 1);
    CloseHandle(process);
  }
  if (g_powerThread.joinable()) g_powerThread.join();
}
#else
void StartPowerMeasurement() {}
CpuPowerSample SampleCpuPower() { return {}; }
double SampleCpuPackagePower() { return -1.0; }
std::vector<CpuPowerSample> TakePowerSamples(uint64_t *dropped) {
  if (dropped) *dropped = 0;
  return {};
}
void ShutdownPowerMeasurement() {}
#endif
