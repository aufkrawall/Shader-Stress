// cli_launcher.c - Tiny console stub that runs ShaderStress.exe --cli
// This passes --cli to force CLI mode (pseudo-GUI like Linux/macOS)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int main(void) {
  // Get path to this executable
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(NULL, path, MAX_PATH);

  // Replace .com with .exe
  size_t len = wcslen(path);
  if (len > 4 && _wcsicmp(path + len - 4, L".com") == 0) {
    wcscpy(path + len - 4, L".exe");
  }

  // Get the original command line and find arguments after exe name
  wchar_t *cmdLine = GetCommandLineW();
  wchar_t *args = cmdLine;

  // Skip past the executable name in command line
  if (*args == L'"') {
    args++;
    while (*args && *args != L'"')
      args++;
    if (*args == L'"')
      args++;
  } else {
    while (*args && *args != L' ')
      args++;
  }
  while (*args == L' ')
    args++;

  // Build new command line: "exe_path" --cli original_args
  // Use StringCchPrintfW for safe string formatting (buffer size limited)
  wchar_t newCmdLine[32768];
  
  // Calculate total length first to check for overflow
  size_t pathLen = wcslen(path);
  size_t argsLen = wcslen(args);
  // Format: "path" --cli args\0
  // Need: 2 quotes + 6 for " --cli " + 1 null + path + args
  if (pathLen + argsLen + 10 > 32767) {
    return 1;  // Command line too long
  }
  
  // Build command line manually (safe against overflow)
  newCmdLine[0] = L'"';
  wcscpy(newCmdLine + 1, path);
  newCmdLine[1 + pathLen] = L'"';
  wcscpy(newCmdLine + 1 + pathLen + 1, L" --cli ");
  wcscpy(newCmdLine + 1 + pathLen + 1 + 7, args);

  // Start the exe with inherited console handles
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION pi = {0};

  if (!CreateProcessW(path, newCmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si,
                      &pi)) {
    return 1;
  }

  // Wait for completion and return its exit code
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exitCode = 0;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return (int)exitCode;
}
