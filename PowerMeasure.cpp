// PowerMeasure.cpp - CPU package power sampling via PowerReader.exe (LHM helper)
// PowerReader.exe is compiled at build time from vendor/lhm/PowerReader.cs.
// It loads LibreHardwareMonitorLib.dll, reads Package power via PawnIO, and
// outputs watts to stdout. Requires admin privileges.
#include "Common.h"

#if defined(_WIN32)
namespace {
std::atomic<double> g_cachedPower{-1.0};
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

double RunPowerReader() {
  wchar_t lhmDir[MAX_PATH];
  GetModuleFileNameW(NULL, lhmDir, MAX_PATH);
  wchar_t *lastSlash = wcsrchr(lhmDir, L'\\');
  if (!lastSlash) return -1.0;
  wcscpy(lastSlash + 1, L"lhm");

  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  HANDLE hRead = NULL, hWrite = NULL;
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1.0;
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
    return -1.0;
  }
  CloseHandle(hWrite);

  // A hung reader must not block this thread forever: kill it on timeout so
  // the pipe closes and ReadFile returns.
  if (!WaitOrStop(pi.hProcess, 8000)) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 2000);
  }
  char buf[64] = {};
  DWORD totalRead = 0;
  ReadFile(hRead, buf, sizeof(buf) - 1, &totalRead, NULL);
  CloseHandle(hRead);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if (totalRead == 0) return -1.0;
  double watts = atof(buf);
  return (watts > 0 && watts < 1000) ? watts : -1.0;
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
  double test = RunPowerReader();
  if (test <= 0) {
    g_App.Log(L"Power: sensor read failed (not admin or PawnIO not working)");
    return;
  }
  g_cachedPower = test;
  g_App.Log(L"Power: sensor OK (" + std::to_wstring((int)test) + L" W)");
  // Sample every 5 s until shutdown signals the stop event.
  while (WaitForSingleObject(g_stopEvent, 5000) == WAIT_TIMEOUT) {
    double watts = RunPowerReader();
    if (watts > 0) g_cachedPower = watts;
  }
}
} // namespace

void StartPowerMeasurement() {
  if (g_powerThread.joinable()) return;
  if (!g_stopEvent) g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent) return;
  ResetEvent(g_stopEvent);
  g_powerThread = std::thread(PowerThreadMain);
}

double SampleCpuPackagePower() { return g_cachedPower.load(); }

void ShutdownPowerMeasurement() {
  if (g_stopEvent) SetEvent(g_stopEvent);
  if (g_powerThread.joinable()) g_powerThread.join();
}
#else
void StartPowerMeasurement() {}
double SampleCpuPackagePower() { return -1.0; }
void ShutdownPowerMeasurement() {}
#endif
