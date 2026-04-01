#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static const wchar_t kCliEnvVar[] = L"SHADERSTRESS_CLI_LAUNCHER";

static const wchar_t *SkipProgramName(const wchar_t *commandLine) {
  if (!commandLine) {
    return L"";
  }

  if (*commandLine == L'"') {
    ++commandLine;
    while (*commandLine && *commandLine != L'"') {
      ++commandLine;
    }
    if (*commandLine == L'"') {
      ++commandLine;
    }
  } else {
    while (*commandLine && *commandLine != L' ' && *commandLine != L'\t') {
      ++commandLine;
    }
  }

  while (*commandLine == L' ' || *commandLine == L'\t') {
    ++commandLine;
  }
  return commandLine;
}

static wchar_t *BuildChildCommandLine(const wchar_t *exePath,
                                      const wchar_t *tail) {
  const size_t exeLen = wcslen(exePath);
  const size_t tailLen = wcslen(tail);
  const size_t totalLen = exeLen + tailLen + 4;
  wchar_t *commandLine = (wchar_t *)malloc(totalLen * sizeof(wchar_t));

  if (!commandLine) {
    return NULL;
  }

  if (tailLen != 0) {
    swprintf(commandLine, totalLen, L"\"%ls\" %ls", exePath, tail);
  } else {
    swprintf(commandLine, totalLen, L"\"%ls\"", exePath);
  }

  return commandLine;
}

static int PrintLauncherError(const wchar_t *message, const wchar_t *path) {
  if (path && *path) {
    fwprintf(stderr, L"%ls %ls\n", message, path);
  } else {
    fwprintf(stderr, L"%ls\n", message);
  }
  return 1;
}

int wmain(void) {
  wchar_t exePath[MAX_PATH];
  DWORD pathLen = GetModuleFileNameW(NULL, exePath, MAX_PATH);
  if (pathLen == 0 || pathLen >= MAX_PATH) {
    return PrintLauncherError(L"ERROR: Failed to resolve ShaderStress.exe.",
                              NULL);
  }

  wchar_t *dot = wcsrchr(exePath, L'.');
  wchar_t *slash = wcsrchr(exePath, L'\\');
  if (!dot || (slash && dot < slash)) {
    return PrintLauncherError(L"ERROR: Invalid launcher path.", exePath);
  }

  dot[1] = L'e';
  dot[2] = L'x';
  dot[3] = L'e';
  dot[4] = L'\0';

  DWORD attrs = GetFileAttributesW(exePath);
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return PrintLauncherError(L"ERROR: ShaderStress.exe not found next to launcher.",
                              exePath);
  }

  const wchar_t *tail = SkipProgramName(GetCommandLineW());
  wchar_t *commandLine = BuildChildCommandLine(exePath, tail);
  if (!commandLine) {
    return PrintLauncherError(L"ERROR: Failed to allocate launcher command line.",
                              NULL);
  }

  SetEnvironmentVariableW(kCliEnvVar, L"1");

  STARTUPINFOW startupInfo = {0};
  PROCESS_INFORMATION processInfo = {0};
  startupInfo.cb = sizeof(startupInfo);

  BOOL launched = CreateProcessW(exePath, commandLine, NULL, NULL, TRUE, 0,
                                 NULL, NULL, &startupInfo, &processInfo);
  free(commandLine);

  if (!launched) {
    return PrintLauncherError(L"ERROR: Failed to launch ShaderStress.exe.",
                              exePath);
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);

  DWORD exitCode = 1;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  return (int)exitCode;
}