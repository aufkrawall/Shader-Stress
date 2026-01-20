// ShaderStress.cpp - Main entry point
// Windows: wWinMain with GDI GUI
// Linux/macOS: main() with CLI
#include "Common.h"
#include "TerminalUtils.h"

#ifdef PLATFORM_WINDOWS

#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "dwmapi")
#pragma comment(lib, "shcore")
#pragma comment(lib, "shell32")
#pragma comment(lib, "dbghelp")

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  g_Scale = GetDpiForSystem() / 96.0f;
  g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
  // Log Header
  g_App.LogRaw(L"--- Session Start (v" + std::wstring(APP_VERSION) + L") ---");
  g_App.LogRaw(L"OS: Windows");
  g_App.LogRaw(L"Architecture: " + GetArchName());

  g_Cpu = GetCpuInfo();
  g_App.sigStatus = g_Cpu.name;

  g_ColdStorage.resize(32 * 1024 * 1024 / 8);
  std::mt19937_64 r(123);
  for (auto &v : g_ColdStorage)
    v = r();

  int argc = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

  // Check for --cli and --verify arguments
  std::wstring verifyHash;
  bool cliMode = false;
  if (argv) {
    for (int i = 1; i < argc; ++i) {
      if (lstrcmpiW(argv[i], L"--cli") == 0)
        cliMode = true;
      if (lstrcmpiW(argv[i], L"--verify") == 0 && i + 1 < argc) {
        verifyHash = argv[i + 1];
      }
      if (lstrcmpiW(argv[i], L"--repro") == 0 && i + 2 < argc) {
        g_Repro.active = true;
        g_Repro.seed = _wtoi64(argv[i + 1]);
        g_Repro.complexity = _wtoi(argv[i + 2]);
      }
      if (lstrcmpiW(argv[i], L"--max-duration") == 0 && i + 1 < argc)
        g_App.maxDuration = _wtoi(argv[i + 1]);
      if (lstrcmpiW(argv[i], L"--no-avx512") == 0)
        g_ForceNoAVX512 = true;
      if (lstrcmpiW(argv[i], L"--no-avx2") == 0)
        g_ForceNoAVX2 = true;
      if (lstrcmpiW(argv[i], L"--help") == 0)
        PrintHelp();
    }
    LocalFree(argv);
  }

  // CLI hash verification mode (quick - doesn't need full CLI)
  if (!verifyHash.empty()) {
    // Attach to parent console for output
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
      FILE *fp;
      freopen_s(&fp, "CONOUT$", "w", stdout);
      freopen_s(&fp, "CONOUT$", "w", stderr);

      std::cout << std::endl; // Separate from shell prompt

      HashResult vr = ValidateBenchmarkHash(verifyHash);
      if (vr.valid) {
        std::cout << "=== VALID HASH ===" << std::endl;
        std::cout << "Version: ShaderStress " << (int)vr.versionMajor << "."
                  << (int)vr.versionMinor << std::endl;
        std::wcout << L"OS: " << GetOsName(vr.os) << std::endl;
        std::wcout << L"Arch: " << GetArchNameFromCode(vr.arch) << std::endl;
        std::cout << "CPU Hash: " << (int)vr.cpuHash << std::endl;
        std::cout << "R0: " << vr.r0 << " jobs/s" << std::endl;
        std::cout << "R1: " << vr.r1 << " jobs/s" << std::endl;
        std::cout << "R2: " << vr.r2 << " jobs/s" << std::endl;
      } else {
        std::cout << "=== INVALID HASH ===" << std::endl;
        std::wcout << L"Hash: " << verifyHash << std::endl;
      }
      std::cout << std::endl;
      FreeConsole();
    }
    return 0;
  }

  // Full CLI mode (pseudo-GUI like Linux/macOS)
  if (cliMode) {
    // Attach to parent console
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
      FILE *fp;
      freopen_s(&fp, "CONOUT$", "w", stdout);
      freopen_s(&fp, "CONOUT$", "w", stderr);
      freopen_s(&fp, "CONIN$", "r", stdin);
    } else {
      AllocConsole();
      FILE *fp;
      freopen_s(&fp, "CONOUT$", "w", stdout);
      freopen_s(&fp, "CONOUT$", "w", stderr);
      freopen_s(&fp, "CONIN$", "r", stdin);
    }

    // Enable ANSI escape sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    std::cout << std::endl;
    std::wcout << L"ShaderStress " << APP_VERSION << std::endl;
    std::wcout << L"CPU: " << g_Cpu.brand << std::endl;

    // Helper for input
    auto AskInput = [](const char *prompt, int def, int min, int max) {
      std::cout << prompt << " [" << def << "]: ";
      std::string line;
      std::getline(std::cin, line);
      if (line.empty())
        return def;
      try {
        int v = std::stoi(line);
        if (v >= min && v <= max)
          return v;
      } catch (...) {
      }
      return def;
    };

    std::cout << "\nSelect Mode:\n"
              << "1. Dynamic\n"
              << "2. Steady\n"
              << "3. Benchmark\n"
              << "4. Verify Hash\n";
    int modeSel = AskInput("Mode", 1, 1, 4);

    if (modeSel == 4) { // Verify Hash
      std::cout << "\nEnter hash (SS3-XXXXXXXXXXXXXXXX): ";
      std::string hashInput;
      std::cin >> hashInput;
      std::wstring whash(hashInput.begin(), hashInput.end());
      HashResult vr = ValidateBenchmarkHash(whash);
      if (vr.valid) {
        std::cout << "\n=== VALID HASH ===\n";
        std::cout << "Version: ShaderStress " << (int)vr.versionMajor << "."
                  << (int)vr.versionMinor << "\n";
        std::wcout << L"OS: " << GetOsName(vr.os) << L"\n";
        std::wcout << L"Arch: " << GetArchNameFromCode(vr.arch) << L"\n";
        std::cout << "CPU Hash: " << (int)vr.cpuHash << "\n";
        std::cout << "R0: " << vr.r0 << " jobs/s\n";
        std::cout << "R1: " << vr.r1 << " jobs/s\n";
        std::cout << "R2: " << vr.r2 << " jobs/s\n";
      } else {
        std::cout << "\n=== INVALID HASH ===\n";
      }
      std::cout << "\nPress Enter to exit...";
      std::cin.ignore();
      std::cin.get();
      FreeConsole();
      return 0;
    }

    if (modeSel == 3) { // Benchmark
      g_App.mode = 0;
      g_App.maxDuration = 180;
    } else {
      g_App.mode = (modeSel == 1) ? 2 : 1;
    }

    // ISA selection - default differs by mode
    int isaDef = (g_App.mode == 0)
                     ? 5
                     : 1; // Benchmark=5 (Scalar realistic), else=1 (Auto)
    std::cout << "\nSelect ISA:\n"
              << "1. Auto\n"
              << "2. AVX-512\n"
              << "3. AVX2\n"
              << "4. Scalar (synthetic)\n"
              << "5. Scalar (realistic)\n";
    int isaSel = AskInput("ISA", isaDef, 1, 5);
    g_App.selectedWorkload = (isaSel - 1);

    DetectBestConfig();

    int cpu = std::thread::hardware_concurrency();
    if (cpu == 0)
      cpu = 4;
    for (int i = 0; i < cpu; ++i)
      g_Workers.push_back(std::make_unique<Worker>());

    std::cout << "\nStarting stress test with " << cpu << " threads..."
              << std::endl;
    std::cout << "Press Ctrl+C to abort." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    g_WdThread = std::make_unique<ThreadWrapper>();
    g_WdThread->t = std::thread(Watchdog);

    g_App.running = true;
    if (g_App.mode == 0) { // Benchmark
      SetWork(cpu, 0, false, false);
    } else if (g_App.mode == 2) { // Dynamic
      g_DynThread = std::make_unique<ThreadWrapper>();
      g_DynThread->t = std::thread(DynamicLoop);
    } else { // Steady
      int d = std::min(4, std::max(1, cpu / 2));
      int c = std::max(0, cpu - d);
      SetWork(c, d, true, true);
    }

    // Dashboard - print static content once, then update only values
    std::cout << "\033[2J\033[H" << std::flush; // Clear screen once
    std::cout << "\033[?25l";                   // Hide cursor

    std::wstring modeName =
        (g_App.mode == 2 ? L"Dynamic"
                         : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
    std::wstring activeISA = GetResolvedISAName(g_App.selectedWorkload);

    // Line 1-4: Static header
    std::wcout << L"Shader Stress " << APP_VERSION << L"\n";
    std::wcout << L"OS: Windows (" << GetArchName() << L")\n";
    std::wcout << L"Mode: " << modeName << L"\n";
    std::wcout << L"Active ISA: " << activeISA << L"\n";
    // Line 5: Jobs Done (value at col 12)
    std::wcout << L"Jobs Done: \n\n";
    // Line 7: Performance header
    std::wcout << L"--- Performance ---\n";
    // Line 8: Rate (value at col 16)
    std::wcout << L"Rate (Jobs/s): \n";
    // Line 9: Time (value at col 7)
    std::wcout << L"Time: \n";

    if (g_App.mode == 0) {
      // Lines 10-15: Benchmark section
      std::wcout << L"\n--- Benchmark Rounds ---\n";
      std::wcout << L"1st Minute: \n";
      std::wcout << L"2nd Minute: \n";
      std::wcout << L"3rd Minute: \n";
      std::wcout << L"Hash: \n";
    }

    // Workers line (dynamic position based on mode)
    int statusLine = (g_App.mode == 0) ? 17 : 11;
    std::cout << "\033[" << statusLine << ";1H";
    std::wcout << L"\n--- Stress Status ---\n";
    std::wcout << L"Workers: \n";
    std::cout << std::flush;

    // Main loop - update only values
    while (!g_App.quit) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));

      // Line 5: Jobs Done value
      std::cout << "\033[5;12H" << std::flush;
      std::wcout << FmtNum(g_App.shaders) << L"          ";

      // Line 8: Rate value
      std::cout << "\033[8;16H" << std::flush;
      std::wcout << FmtNum(g_App.currentRate) << L"          ";

      // Line 9: Time value
      std::cout << "\033[9;7H" << std::flush;
      std::wcout << FmtTime(g_App.elapsed) << L"          ";

      if (g_App.mode == 0) { // Benchmark
        // Line 12-14: Benchmark round values
        std::cout << "\033[12;13H" << std::flush;
        std::wcout << (g_App.benchRates[0] > 0 ? FmtNum(g_App.benchRates[0])
                                               : L"-")
                   << L"          ";
        std::cout << "\033[13;13H" << std::flush;
        std::wcout << (g_App.benchRates[1] > 0 ? FmtNum(g_App.benchRates[1])
                                               : L"-")
                   << L"          ";
        std::cout << "\033[14;13H" << std::flush;
        std::wcout << (g_App.benchRates[2] > 0 ? FmtNum(g_App.benchRates[2])
                                               : L"-")
                   << L"          ";

        // Line 15: Hash
        if (!g_App.benchHash.empty()) {
          std::cout << "\033[15;7H" << std::flush;
          std::wcout << g_App.benchHash << L" (v" << APP_VERSION << L")";
        }

        if (g_App.benchComplete) {
          std::cout << "\033[16;1H" << std::flush;
          std::wcout << L"\nWINNER: Interval " << (g_App.benchWinner + 1)
                     << L"\n";
          break;
        }

        // Benchmark workers at line 19
        std::cout << "\033[19;10H" << std::flush;
        std::wcout << (g_App.activeCompilers + g_App.activeDecomp) << L"    ";

        // Check if time expired
        if (g_App.maxDuration > 0) {
          int remaining = g_App.maxDuration - (int)(g_App.elapsed / 1000);
          if (remaining <= 0)
            break;
        }
      } else {
        // Non-benchmark worker line
        std::cout << "\033[" << (statusLine + 2) << ";10H" << std::flush;
        std::wcout << (g_App.activeCompilers + g_App.activeDecomp) << L"    ";
      }

      std::wcout << std::flush;
    }
    std::cout << "\033[?25h"; // Show cursor

    // Cleanup
    g_App.quit = true;
    for (auto &w : g_Workers)
      w->terminate = true;
    for (auto &w : g_IOThreads)
      w->terminate = true;
    g_RAM.terminate = true;
    g_DynThread.reset();
    g_WdThread.reset();
    g_Threads.clear();

    std::cout << "\n=== Final Results ===\n";
    std::cout << "Total Jobs: " << (long long)g_App.shaders << "\n";
    std::cout << "Avg Rate: " << (int)g_App.currentRate << " jobs/s\n";

    if (g_App.mode == 0 && !g_App.benchHash.empty()) {
      std::wcout << L"\nBenchmark Hash: " << g_App.benchHash << L"\n";
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
    std::cin.get();
    FreeConsole();
    return 0;
  }

  DetectBestConfig();

  int cpu = std::thread::hardware_concurrency();
  if (cpu == 0)
    cpu = 4;
  // Workers (Data)
  for (int i = 0; i < cpu; ++i)
    g_Workers.push_back(std::make_unique<Worker>());

  // Thread spawning is now fully managed by SetWork() to enforce strict thread
  // limits

  // RAM/IO threads spawned dynamically in SetWork

  if (g_Repro.active) {
    g_App.Log(L"Repro Mode Active. Running workload...");
    std::this_thread::sleep_for(11s);
    g_App.Log(L"Repro finished without crash.");
    goto cleanup;
  }

  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);

  {
    WNDCLASSW wc{
        0,       WndProc, 0,     0, inst, nullptr, LoadCursor(0, IDC_ARROW),
        nullptr, nullptr, L"SST"};
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
    RegisterClassW(&wc);
    InitGDI();

    RECT rc = {0, 0, S(760), S(710)};
    DWORD style =
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
    AdjustWindowRect(&rc, style, FALSE);
    int wW = rc.right - rc.left;
    int wH = rc.bottom - rc.top;

    g_MainWindow = CreateWindowW(L"SST", L"Shader Stress", style,
                                 (GetSystemMetrics(SM_CXSCREEN) - wW) / 2,
                                 (GetSystemMetrics(SM_CYSCREEN) - wH) / 2, wW,
                                 wH, 0, 0, inst, 0);

    BOOL dark = TRUE;
    DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark,
                          sizeof(dark));
    SetTimer(g_MainWindow, 1, 500, nullptr); // UI Update Timer (500ms)
    MSG msg;
    while (GetMessage(&msg, 0, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    CleanupGDI();
  }

cleanup:
  // Cleanup for GUI mode
  g_App.quit = true;
  for (auto &w : g_Workers)
    w->terminate = true;
  for (auto &w : g_IOThreads)
    w->terminate = true;
  g_RAM.terminate = true;
  g_DynThread.reset();
  g_WdThread.reset();
  g_Threads.clear();
  return 0;
}

#else // Linux/macOS CLI

#include <filesystem>
#include <iostream>
#include <locale>
#include <signal.h>

// ... signalHandler ...

static void signalHandler(int sig) {
  (void)sig;
  g_App.quit = true;
  g_App.running = false;
}

static int AskInput(const std::string &prompt, int def, int min, int max) {
  std::cout << prompt << " [" << def << "]: ";
  std::string line;
  std::getline(std::cin, line);
  if (line.empty())
    return def;
  try {
    int v = std::stoi(line);
    if (v >= min && v <= max)
      return v;
  } catch (...) {
  }
  return def;
}

int main(int argc, char *argv[]) {
#if defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)
  if (!IsRunningInTerminal() && !ShouldSkipTerminalSpawn(argc, argv)) {
    if (TrySpawnTerminal(argc, argv)) {
      return 0;
    }
    ShowTerminalRequiredError();
    return 1;
  }
#endif

  // Setup Locale and Logging
  try {
    // Try forcing UTF-8 locale for consistent wide-char handling on macOS
    std::locale::global(std::locale("en_US.UTF-8"));
  } catch (...) {
    std::setlocale(LC_ALL, ""); // Fallback
  }
  // Log actual locale for debugging
  const char *activeLocale = std::setlocale(LC_ALL, nullptr);
  std::cout << "Active Locale: " << (activeLocale ? activeLocale : "Unknown")
            << std::endl;

  std::cout << "Working Directory: " << std::filesystem::current_path()
            << std::endl;

  g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
  if (!g_App.log.is_open()) {
    std::cerr << "ERROR: Failed to open ShaderStress.log for writing!"
              << std::endl;
    perror("Reason"); // Print system error (permission denied, etc)
  }

  // Log Header
  g_App.LogRaw(L"--- Session Start (v" + std::wstring(APP_VERSION) + L") ---");
#ifdef PLATFORM_LINUX
  g_App.LogRaw(L"OS: Linux");
#else
  g_App.LogRaw(L"OS: macOS");
#endif
  g_App.LogRaw(L"Architecture: " + GetArchName());

  struct sigaction sa;
  sa.sa_handler = signalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; // No SA_RESTART -> interrupts sleep/read calls
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  g_Cpu = GetCpuInfo();
  g_App.sigStatus = g_Cpu.name;
  g_App.LogRaw(L"CPU: " + g_Cpu.brand);

  // Print startup info to console
  std::wcout << L"ShaderStress " << APP_VERSION << std::endl;
  std::wcout << L"CPU: " << g_Cpu.brand << std::endl;

  // Cold Storage Init
  g_ColdStorage.resize(32 * 1024 * 1024 / 8);
  std::mt19937_64 r(123);
  for (auto &v : g_ColdStorage)
    v = r();

  bool batchMode = false;
  int duration = -1;

  // Parse args
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
      duration = atoi(argv[++i]);
      if (duration > 0)
        g_App.maxDuration = duration;
      batchMode = true;
    }
    if (strcmp(argv[i], "--benchmark") == 0) {
      g_App.mode = 0;
      g_App.selectedWorkload =
          WL_SCALAR_SIM; // Force realistic scalar for benchmark
      duration = 180;
      batchMode = true;
    }
    if (strcmp(argv[i], "--help") == 0) {
      std::cout << "Usage: shaderstress [options]" << std::endl;
      std::cout << "  --duration <sec>   Run for N seconds" << std::endl;
      std::cout << "  --benchmark        Run 3-minute benchmark" << std::endl;
      std::cout << "  --force-no-spawn   Skip terminal auto-spawn (for scripts)" << std::endl;
      return 0;
    }
  }

  // Interactive Menu (if not in batch mode via args)
  if (!batchMode) {
    std::cout << "\nSelect Mode:\n"
              << "1. Dynamic\n"
              << "2. Steady\n"
              << "3. Benchmark\n"
              << "4. Verify Hash\n";
    int modeSel = AskInput("Mode", 1, 1, 4);

    if (modeSel == 4) { // Verify Hash
      std::cout << "\nEnter hash to verify (format: SS3-XXXXXXXXXXX): ";
      std::string hashInput;
      std::cin >> hashInput;
      std::wstring whash(hashInput.begin(), hashInput.end());

      HashResult vr = ValidateBenchmarkHash(whash);

      if (vr.valid) {
        std::cout << "\n=== VALID HASH ===\n";
        std::cout << "Version: ShaderStress " << (int)vr.versionMajor << "."
                  << (int)vr.versionMinor << "\n";
        std::wcout << L"OS: " << GetOsName(vr.os) << L"\n";
        std::wcout << L"Arch: " << GetArchNameFromCode(vr.arch) << L"\n";
        std::cout << "CPU Hash: " << (int)vr.cpuHash << "\n";
        std::cout << "Algorithm: Base62 + FNV1a Checksum\n\n";

        std::cout << "--- Benchmark Scores ---\n";
        std::cout << "1st Minute: " << vr.r0 << " jobs/s\n";
        std::cout << "2nd Minute: " << vr.r1 << " jobs/s\n";
        std::cout << "3rd Minute: " << vr.r2 << " jobs/s\n";

        if (vr.versionMajor != APP_VERSION_MAJOR ||
            vr.versionMinor != APP_VERSION_MINOR) {
          std::cout << "\n(Note: Hash is from a different version)\n";
        }
      } else {
        std::cout << "\n=== INVALID HASH ===\n";
        std::cout << "The hash \"" << hashInput
                  << "\" could not be verified.\n\n";
        std::cout << "Possible reasons:\n";
        std::cout << "- Hash is corrupted or incomplete\n";
        std::cout << "- Hash was manually modified\n";
      }

      std::cout << "\nPress Enter to exit...";
      std::cin.ignore();
      std::cin.get();
      return 0;
    }

    if (modeSel == 3) { // Benchmark
      g_App.mode = 0;
      // Pre-select Scalar (realistic) which is option 5
      int isaDef = 5;
      std::cout << "\nSelect ISA:\n"
                << "1. Auto\n"
                << "2. AVX-512\n"
                << "3. AVX2\n"
                << "4. Scalar (synthetic)\n"
                << "5. Scalar (realistic)\n";
      int isaSel = AskInput("ISA", isaDef, 1, 5);
      g_App.selectedWorkload = (isaSel - 1);
    } else {
      g_App.mode = (modeSel == 1) ? 2 : 1; // 1->Dynamic(2), 2->Steady(1)

      std::cout << "\nSelect ISA:\n"
                << "1. Auto\n"
                << "2. AVX-512\n"
                << "3. AVX2\n"
                << "4. Scalar (synthetic)\n"
                << "5. Scalar (realistic)\n";
      int isaDef = 1;
      int isaSel = AskInput("ISA", isaDef, 1, 5);

      // Map 1..5 to Enums (Auto=0, 512=1, AVX2=2, ScaMath=3, ScaSim=4)
      g_App.selectedWorkload = (isaSel - 1);
    }
  }

  DetectBestConfig(); // Set g_ActiveConfig

  int cpu = std::thread::hardware_concurrency();
  if (cpu == 0)
    cpu = 4;

  std::cout << "\nStarting stress test with " << cpu << " threads..."
            << std::endl;
  if (!batchMode)
    std::cout << "Press Ctrl+C to abort." << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // Initialize Threads
  for (int i = 0; i < cpu; ++i)
    g_Workers.push_back(std::make_unique<Worker>());

  // Start workers

  // IO/RAM threads are spawned lazily when first activated (see Threading.cpp)
  // This avoids thread overhead during benchmark mode or compute-only phases

  // Watchdog & Start
  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);

  g_App.running = true;
  if (g_App.mode == 0) { // Benchmark setup
    SetWork(cpu, 0, false, false);
  } else if (g_App.mode == 2) { // Dynamic
    g_DynThread = std::make_unique<ThreadWrapper>();
    g_DynThread->t = std::thread(DynamicLoop);
  } else { // Steady
    // Default steady: 50/50 comp/decom? Or just full comp?
    // Gui logic for Steady: SetWork(std::max(0, cpu - d), d, true, true); where
    // d is half Let's stick to simple full load for steady unless we want to
    // replicate Gui exactly Gui "Steady" button does: SetWork(c, d, true, true)
    // where d=min(4, max(1, cpu/2))
    int d = std::min(4, std::max(1, cpu / 2));
    int c = std::max(0, cpu - d);
    SetWork(c, d, true, true);
  }

  // Dashboard Loop
  std::cout << "\033[?25l"; // Hide cursor
  while (!g_App.quit) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Clear screen (using cout/narrow for raw ANSI bytes to avoid wide-char
    // buffering issues on macOS)
    std::cout << "\033[2J\033[H" << std::flush;

    // Header
    std::wcout << L"Shader Stress " << APP_VERSION << L"\n";
#ifdef PLATFORM_LINUX
    std::wcout << L"OS: Linux (" << GetArchName() << L")\n";
#else
    std::wcout << L"OS: macOS (" << GetArchName() << L")\n";
#endif

    std::wstring modeName =
        (g_App.mode == 2 ? L"Dynamic"
                         : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
    std::wstring activeISA = GetResolvedISAName(g_App.selectedWorkload);

    std::wcout << L"Mode: " << modeName << L"\n";
    std::wcout << L"Active ISA: " << activeISA << L"\n";
    std::wcout << L"Jobs Done: " << FmtNum(g_App.shaders) << L"\n\n";

    std::wcout << L"--- Performance ---\n";
    std::wcout << L"Rate (Jobs/s): " << FmtNum(g_App.currentRate) << L"\n";
    std::wcout << L"Time: " << FmtTime(g_App.elapsed) << L"\n";

    if (g_App.mode == 2) {
      std::wcout << L"Phase: " << g_App.currentPhase << L" / 15\n";
      std::wcout << L"Loop: " << g_App.loops << L"\n";
    } else if (g_App.mode == 0) {
      std::wcout << L"\n--- Benchmark Rounds ---\n";
      std::wcout << L"1st Minute: "
                 << (g_App.benchRates[0] > 0 ? FmtNum(g_App.benchRates[0])
                                             : L"-")
                 << L"\n";
      std::wcout << L"2nd Minute: "
                 << (g_App.benchRates[1] > 0 ? FmtNum(g_App.benchRates[1])
                                             : L"-")
                 << L"\n";
      std::wcout << L"3rd Minute: "
                 << (g_App.benchRates[2] > 0 ? FmtNum(g_App.benchRates[2])
                                             : L"-")
                 << L"\n";

      if (!g_App.benchHash.empty()) {
        std::wcout << L"Hash: " << g_App.benchHash << L" (v" << APP_VERSION
                   << L")\n";
      }

      if (g_App.benchComplete) {
        std::wcout << L"\nWINNER: Interval " << (g_App.benchWinner + 1)
                   << L"\n";
      }
    }

    std::wcout << L"\n--- Stress Status ---\n";
    std::wcout << L"Workers: " << (g_App.activeCompilers + g_App.activeDecomp)
               << L"\n";
    std::wcout << L" > Sim Compilers: " << g_App.activeCompilers << L"\n";
    std::wcout << L" > Decompressors: " << g_App.activeDecomp << L"\n";
    std::wcout << L"RAM Thread: " << (g_App.ramActive ? L"ACTIVE" : L"Idle")
               << L"\n";
    std::wcout << L"I/O Threads: " << (g_App.ioActive ? L"ACTIVE" : L"Idle")
               << L"\n";

    if (g_App.errors > 0)
      std::wcout << L"\nErrors: " << FmtNum(g_App.errors) << L" !!!\n";
    else
      std::wcout << L"\nErrors: 0\n";

    std::wcout << L"\n[Press Ctrl+C to abort]" << std::flush;

    if (duration > 0 && (int)g_App.elapsed >= duration)
      g_App.quit = true;

    if (g_App.mode == 0 && g_App.benchComplete) {
      // Wait a bit then exit? Or just wait for user?
      // Bench mode implies auto-exit in CLI usually, but Gui stays open.
      // User asked for "Run 3-minute benchmark" CLI arg implies exit.
      // But if interactive, maybe stay?
      // For now, if duration was set (legacy arg), we exit.
      // If purely interactive benchmark, we loop until Ctrl+C.
      // Gui.cpp doesn't auto-close.
    }
  }

  std::cout << "\033[?25h"; // Show cursor
  std::cout << "\nStopping...\n";

  // Cleanup
  g_App.quit = true;
  g_App.running = false;
  for (auto &w : g_Workers)
    w->terminate = true;
  for (auto &w : g_IOThreads)
    w->terminate = true;
  g_RAM.terminate = true;
  g_WdThread.reset();
  g_DynThread.reset();
  g_Threads.clear();

  std::cout << "Total jobs completed: " << g_App.shaders << std::endl;
  return 0;
}

#endif // PLATFORM_WINDOWS
