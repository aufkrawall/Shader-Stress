// ShaderStress.cpp - Main entry point
// Windows ships a GUI-first ShaderStress.exe plus a tiny ShaderStress.com
// launcher for terminal CLI use.
// Linux/macOS: CLI with optional terminal auto-spawn for the interactive wizard.
#include "app/Cli.h"
#include "app/TerminalUtils.h"

#ifdef PLATFORM_WINDOWS
#include <fcntl.h>
#include <io.h>
#endif

namespace {
#ifdef PLATFORM_WINDOWS
struct WindowsHandleState {
  HANDLE handle = INVALID_HANDLE_VALUE;
  bool valid = false;
  bool console = false;
  bool redirected = false;
};

WindowsHandleState QueryWindowsHandle(DWORD stdId) {
  WindowsHandleState state;
  state.handle = GetStdHandle(stdId);
  if (!state.handle || state.handle == INVALID_HANDLE_VALUE) {
    state.handle = INVALID_HANDLE_VALUE;
    return state;
  }
  DWORD type = GetFileType(state.handle);
  if (type == FILE_TYPE_UNKNOWN && GetLastError() != NO_ERROR) {
    state.handle = INVALID_HANDLE_VALUE;
    return state;
  }
  state.valid = true;
  if (type == FILE_TYPE_CHAR) {
    DWORD mode = 0;
    state.console = GetConsoleMode(state.handle, &mode) != 0;
  } else if (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK) {
    state.redirected = true;
  }
  return state;
}

CliEnvironment QueryWindowsEnvironment() {
  WindowsHandleState in = QueryWindowsHandle(STD_INPUT_HANDLE);
  WindowsHandleState out = QueryWindowsHandle(STD_OUTPUT_HANDLE);
  WindowsHandleState err = QueryWindowsHandle(STD_ERROR_HANDLE);
  CliEnvironment env;
  env.stdinTty = in.console;
  env.stdoutTty = out.console;
  env.stderrTty = err.console;
  env.canPrompt = in.console && out.console;
  env.hasUsableOutput = out.console || out.redirected || err.console || err.redirected;
  env.launchedFromTerminal = in.console || in.redirected || out.console || out.redirected ||
                             err.console || err.redirected;
  return env;
}

bool IsWindowsCliLauncherActive() {
  wchar_t value[8] = {};
  return GetEnvironmentVariableW(L"SHADERSTRESS_CLI_LAUNCHER", value,
                                 static_cast<DWORD>(std::size(value))) > 0;
}

std::vector<std::wstring> GetWindowsArgs() {
  int argc = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::vector<std::wstring> args;
  args.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i)
    args.push_back(argv[i]);
  if (argv)
    LocalFree(argv);
  return args;
}

bool BindHandleToFd(HANDLE handle, int targetFd, int openFlags) {
  HANDLE dupHandle = INVALID_HANDLE_VALUE;
  if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &dupHandle, 0, TRUE,
                       DUPLICATE_SAME_ACCESS))
    return false;
  int fd = _open_osfhandle(reinterpret_cast<intptr_t>(dupHandle), openFlags);
  if (fd == -1) {
    CloseHandle(dupHandle);
    return false;
  }
  if (_dup2(fd, targetFd) != 0) {
    _close(fd);
    return false;
  }
  _close(fd);
  return true;
}

void ConfigureWindowsConsoleForCli() {
  SetConsoleCP(CP_UTF8);
  SetConsoleOutputCP(CP_UTF8);
  std::cin.clear();
  std::wcin.clear();
  std::cout.clear();
  std::cerr.clear();
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (GetConsoleMode(hOut, &mode))
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

CliEnvironment PrepareWindowsCliEnvironment(bool requireInput) {
  WindowsHandleState originalIn = QueryWindowsHandle(STD_INPUT_HANDLE);
  WindowsHandleState originalOut = QueryWindowsHandle(STD_OUTPUT_HANDLE);
  WindowsHandleState originalErr = QueryWindowsHandle(STD_ERROR_HANDLE);

  const bool attachedConsole = AttachConsole(ATTACH_PARENT_PROCESS) != 0;
  FILE *filePtr = nullptr;
  if (attachedConsole && !originalOut.redirected)
    freopen_s(&filePtr, "CONOUT$", "w", stdout);
  else if (originalOut.redirected)
    BindHandleToFd(originalOut.handle, 1, _O_TEXT);
  if (attachedConsole && !originalErr.redirected)
    freopen_s(&filePtr, "CONOUT$", "w", stderr);
  else if (originalErr.redirected)
    BindHandleToFd(originalErr.handle, 2, _O_TEXT);
  if (requireInput) {
    if (originalIn.redirected)
      BindHandleToFd(originalIn.handle, 0, _O_TEXT);
    else if (attachedConsole)
      freopen_s(&filePtr, "CONIN$", "r", stdin);
  }
  clearerr(stdin);
  std::cin.clear();
  std::wcin.clear();
  std::cout.clear();
  std::cerr.clear();
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  ConfigureWindowsConsoleForCli();
  return QueryWindowsEnvironment();
}

int PrintWindowsCliRedirectNotice() {
  const std::wstring message = L"Windows command-line usage is provided by ShaderStress.com.\n\n"
                               L"Run ShaderStress.com --help for usage.";
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    FILE *fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    std::cerr << ToNarrow(message) << '\n';
    FreeConsole();
  } else {
    MessageBoxW(nullptr, message.c_str(), L"Use ShaderStress.com", MB_OK | MB_ICONINFORMATION);
  }
  return (int)CliExitCode::InvalidArguments;
}

int RunWindowsGui() {
  HINSTANCE inst = GetModuleHandleW(nullptr);
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  g_Scale = GetDpiForSystem() / 96.0f;

  InitializeRuntime(false);
  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();
  CreateWorkerPool();

  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);

  WNDCLASSW wc{0, WndProc, 0, 0, inst, nullptr, LoadCursor(0, IDC_ARROW), nullptr, nullptr,
               L"SST"};
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
  RegisterClassW(&wc);
  InitGDI();

  RECT rc = {0, 0, S(760), S(730)};
  DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
  AdjustWindowRect(&rc, style, FALSE);
  int windowWidth = rc.right - rc.left;
  int windowHeight = rc.bottom - rc.top;
  g_MainWindow = CreateWindowW(L"SST", L"Shader Stress", style,
                               (GetSystemMetrics(SM_CXSCREEN) - windowWidth) / 2,
                               (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2, windowWidth,
                               windowHeight, 0, 0, inst, 0);
  BOOL dark = TRUE;
  DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
  SetTimer(g_MainWindow, 1, 500, nullptr);

  MSG msg;
  while (GetMessage(&msg, 0, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  CleanupGDI();
  CleanupWorkers();
  return 0;
}
#endif
} // namespace

#ifdef PLATFORM_WINDOWS
int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
  std::vector<std::wstring> args = GetWindowsArgs();
  if (!IsWindowsCliLauncherActive()) {
    if (args.size() > 1)
      return PrintWindowsCliRedirectNotice();
    return RunWindowsGui();
  }

  CliParseResult parsed = ParseCliArgs(args);
  const bool hadArgs = args.size() > 1;
  CliEnvironment runtimeEnv = PrepareWindowsCliEnvironment(!hadArgs || parsed.options.forceWizard);
  if (!parsed.errors.empty()) {
    for (const auto &error : parsed.errors)
      std::cerr << "Error: " << ToNarrow(error) << '\n';
    std::cerr << "Use --help to see the supported command line options." << '\n';
    return (int)CliExitCode::InvalidArguments;
  }
  return RunCliCommand(parsed.options, runtimeEnv, !hadArgs);
}
#else
int main(int argc, char *argv[]) {
  std::vector<std::wstring> args;
  args.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i)
    args.push_back(ToWide(argv[i] ? std::string(argv[i]) : std::string()));

  CliParseResult parsed = ParseCliArgs(args);
  const bool hadArgs = argc > 1;
  CliEnvironment env;
  env.stdinTty = isatty(STDIN_FILENO) != 0;
  env.stdoutTty = isatty(STDOUT_FILENO) != 0;
  env.stderrTty = isatty(STDERR_FILENO) != 0;
  env.canPrompt = env.stdinTty && env.stdoutTty;
  env.hasUsableOutput = true;
  env.launchedFromTerminal = env.stdinTty || env.stdoutTty || env.stderrTty;

  const bool implicitWizard = !hadArgs;
  const bool needsInteractiveTerminal = implicitWizard || parsed.options.forceWizard;
  if (needsInteractiveTerminal && !env.canPrompt && !parsed.options.skipTerminalSpawn) {
    if (TrySpawnTerminal(argc, argv))
      return 0;
    ShowTerminalRequiredError();
    return (int)CliExitCode::EnvironmentError;
  }
  if (!parsed.errors.empty()) {
    for (const auto &error : parsed.errors)
      std::cerr << "Error: " << ToNarrow(error) << '\n';
    std::cerr << "Use --help to see the supported command line options." << '\n';
    return (int)CliExitCode::InvalidArguments;
  }
  return RunCliCommand(parsed.options, env, implicitWizard);
}
#endif
