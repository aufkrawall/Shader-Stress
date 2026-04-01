// ShaderStress.cpp - Main entry point
// Windows ships a GUI-first ShaderStress.exe plus a tiny ShaderStress.com
// launcher for terminal CLI use.
// Linux/macOS: CLI with optional terminal auto-spawn for the interactive wizard.
#include "Common.h"
#include "TerminalUtils.h"

#include <algorithm>
#include <chrono>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <iostream>
#include <limits>
#include <locale>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifdef PLATFORM_WINDOWS
#include <fcntl.h>
#include <io.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

namespace {

enum class CliExitCode : int {
  Success = 0,
  InvalidArguments = 2,
  EnvironmentError = 3,
  VerificationFailed = 4,
  Interrupted = 130,
};

struct CliOptions {
  bool showHelp = false;
  bool showVersion = false;
  bool forceWizard = false;
  bool quiet = false;
  bool skipTerminalSpawn = false;
  bool runRequested = false;
  bool benchmarkRequested = false;
  bool verifyRequested = false;
  bool reproRequested = false;
  bool hasMode = false;
  bool hasIsa = false;
  bool hasDuration = false;
  bool hasMaxDuration = false;
  bool noAvx512 = false;
  bool noAvx2 = false;
  int mode = 2;
  WorkloadType workload = WL_AUTO;
  uint64_t durationSeconds = 0;
  uint64_t maxDurationSeconds = 0;
  uint64_t reproSeed = 0;
  int reproComplexity = 0;
  std::wstring verifyHash;
};

struct CliParseResult {
  CliOptions options;
  std::vector<std::wstring> errors;
};

struct CliEnvironment {
  bool stdinTty = false;
  bool stdoutTty = false;
  bool stderrTty = false;
  bool launchedFromTerminal = false;
  bool canPrompt = false;
  bool hasUsableOutput = false;
};

struct CliDashboardLayout {
  bool benchmark = false;
  int finalLine = 0;
};

#ifdef PLATFORM_WINDOWS
struct WindowsHandleState {
  HANDLE handle = INVALID_HANDLE_VALUE;
  bool valid = false;
  bool console = false;
  bool redirected = false;
};
#endif

constexpr int kDefaultCliMode = 2;

#ifdef PLATFORM_WINDOWS
constexpr wchar_t kProgramInvocation[] = L"ShaderStress.com";
#else
constexpr wchar_t kProgramInvocation[] = L"./shaderstress";
#endif

#ifndef PLATFORM_WINDOWS
static volatile sig_atomic_t g_SignalReceived = 0;

static void SignalHandler(int sig) {
  (void)sig;
  g_SignalReceived = 1;
  g_App.quit = true;
  g_App.running = false;
}

static void InstallSignalHandlers() {
  struct sigaction sa;
  sa.sa_handler = SignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
}
#else
static bool g_WindowsInterrupted = false;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
  switch (ctrlType) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    g_WindowsInterrupted = true;
    g_App.quit = true;
    g_App.running = false;
    return TRUE;
  default:
    return FALSE;
  }
}
#endif

static bool WasInterrupted() {
#ifdef PLATFORM_WINDOWS
  return g_WindowsInterrupted;
#else
  return g_SignalReceived != 0;
#endif
}

static std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t ch) { return (wchar_t)std::towlower(ch); });
  return value;
}

static std::wstring ToWide(const std::string &value) {
  return std::wstring(value.begin(), value.end());
}

#ifndef PLATFORM_WINDOWS
static std::wstring ToWide(const char *value) {
  if (!value)
    return {};
  return std::wstring(value, value + std::strlen(value));
}
#endif

static std::optional<uint64_t> ParseUint64(const std::wstring &text) {
  try {
    size_t pos = 0;
    unsigned long long parsed = std::stoull(text, &pos, 10);
    if (pos != text.size())
      return std::nullopt;
    return static_cast<uint64_t>(parsed);
  } catch (...) {
    return std::nullopt;
  }
}

static std::optional<int> ParsePositiveInt(const std::wstring &text) {
  try {
    size_t pos = 0;
    long long parsed = std::stoll(text, &pos, 10);
    if (pos != text.size() || parsed <= 0 ||
        parsed > std::numeric_limits<int>::max()) {
      return std::nullopt;
    }
    return static_cast<int>(parsed);
  } catch (...) {
    return std::nullopt;
  }
}

static std::optional<int> ParseModeValue(const std::wstring &text) {
  const std::wstring lowered = ToLowerCopy(text);
  if (lowered == L"dynamic")
    return 2;
  if (lowered == L"steady")
    return 1;
  if (lowered == L"benchmark")
    return 0;
  return std::nullopt;
}

static std::optional<WorkloadType> ParseIsaValue(const std::wstring &text) {
  const std::wstring lowered = ToLowerCopy(text);
  if (lowered == L"auto")
    return WL_AUTO;
  if (lowered == L"avx512" || lowered == L"avx-512")
    return WL_AVX512;
  if (lowered == L"avx2" || lowered == L"avx-2")
    return WL_AVX2;
  if (lowered == L"scalar" || lowered == L"scalar-synthetic" ||
      lowered == L"scalar_synthetic") {
    return WL_SCALAR;
  }
  if (lowered == L"scalar-sim" || lowered == L"scalar_sim" ||
      lowered == L"scalar-realistic" || lowered == L"realistic") {
    return WL_SCALAR_SIM;
  }
  return std::nullopt;
}

static int ModeToWizardChoice(int mode) {
  if (mode == 1)
    return 2;
  if (mode == 0)
    return 3;
  return 1;
}

static int WorkloadToWizardChoice(WorkloadType workload) {
  switch (workload) {
  case WL_AVX512:
    return 2;
  case WL_AVX2:
    return 3;
  case WL_SCALAR:
    return 4;
  case WL_SCALAR_SIM:
    return 5;
  case WL_AUTO:
  default:
    return 1;
  }
}

static WorkloadType MapWizardIsaChoice(int choice) {
  switch (choice) {
  case 2:
    return WL_AVX512;
  case 3:
    return WL_AVX2;
  case 4:
    return WL_SCALAR;
  case 5:
    return WL_SCALAR_SIM;
  case 1:
  default:
    return WL_AUTO;
  }
}

static std::wstring GetModeName(int mode) {
  switch (mode) {
  case 0:
    return L"Benchmark";
  case 1:
    return L"Steady";
  case 2:
  default:
    return L"Dynamic";
  }
}

static std::wstring GetRuntimeOsName() {
#ifdef PLATFORM_WINDOWS
  return L"Windows";
#elif defined(PLATFORM_LINUX)
  return L"Linux";
#else
  return L"macOS";
#endif
}

static void PrintCliVersion() {
  std::wcout << L"ShaderStress " << APP_VERSION << std::endl;
}

static void PrintCliHelp() {
  PrintCliVersion();
  std::wcout << L"\nUsage:\n";
  std::wcout << L"  " << kProgramInvocation << L"\n";
  std::wcout << L"  " << kProgramInvocation << L" --wizard [options]\n";
  std::wcout << L"  " << kProgramInvocation
             << L" --mode <dynamic|steady|benchmark> [options]\n";
  std::wcout << L"  " << kProgramInvocation << L" --benchmark\n";
  std::wcout << L"  " << kProgramInvocation << L" --verify <hash>\n";
  std::wcout << L"  " << kProgramInvocation
             << L" --repro <seed> <complexity> [options]\n";
  std::wcout << L"\nLaunch behavior:\n";
#ifdef PLATFORM_WINDOWS
  std::wcout << L"  - No arguments from Explorer or a shortcut open the GUI.\n";
  std::wcout << L"  - Use ShaderStress.com from a terminal to open the interactive CLI wizard.\n";
  std::wcout << L"  - Use ShaderStress.com for explicit Windows CLI commands.\n";
#else
  std::wcout << L"  - No arguments open the interactive CLI wizard.\n";
  std::wcout << L"  - If launched without a terminal and the wizard is needed,\n";
  std::wcout << L"    ShaderStress will try to spawn one unless --force-no-spawn is used.\n";
#endif
  std::wcout << L"\nCommands and options:\n";
  std::wcout << L"  --wizard                 Force the interactive CLI wizard.\n";
  std::wcout << L"  --mode <name>            Run without prompts. Values: dynamic, steady, benchmark.\n";
  std::wcout << L"  --isa <name>             Select ISA. Values: auto, avx512, avx2, scalar, scalar-sim.\n";
  std::wcout << L"  --duration <sec>         Stop after N seconds.\n";
  std::wcout << L"  --max-duration <sec>     CLI alias of --duration.\n";
  std::wcout << L"  --benchmark              Shortcut for --mode benchmark. Benchmark is always 180 seconds and defaults to scalar-sim unless --isa is provided.\n";
  std::wcout << L"  --verify <hash>          Decode and validate a benchmark hash.\n";
  std::wcout << L"  --repro <seed> <complexity>\n";
  std::wcout << L"                           Run one reproducible workload case.\n";
  std::wcout << L"  --no-avx512              Disable AVX-512 use.\n";
  std::wcout << L"  --no-avx2                Disable AVX2 use.\n";
  std::wcout << L"  --quiet                  Suppress the live dashboard and startup banner.\n";
  std::wcout << L"  --version                Print version and exit.\n";
  std::wcout << L"  --help                   Print this help text and exit.\n";
#if !defined(PLATFORM_WINDOWS)
  std::wcout << L"  --force-no-spawn         Do not auto-spawn a terminal for the wizard.\n";
#endif
  std::wcout << L"\nExit codes:\n";
  std::wcout << L"  0   Success\n";
  std::wcout << L"  2   Invalid arguments\n";
  std::wcout << L"  3   Environment/setup problem\n";
  std::wcout << L"  4   Hash verification failed\n";
  std::wcout << L"  130 Interrupted by Ctrl+C or a termination signal\n";
  std::wcout << L"\nExamples:\n";
  std::wcout << L"  " << kProgramInvocation << L" --wizard\n";
  std::wcout << L"  " << kProgramInvocation
             << L" --mode steady --isa avx2 --duration 60\n";
  std::wcout << L"  " << kProgramInvocation << L" --benchmark\n";
  std::wcout << L"  " << kProgramInvocation
             << L" --repro 12345 1000 --isa scalar\n";
}

static void AddError(std::vector<std::wstring> &errors, const std::wstring &msg) {
  errors.push_back(msg);
}

static CliParseResult ParseCliArgs(const std::vector<std::wstring> &args) {
  CliParseResult result;
  bool sawLegacyCliFlag = false;

  for (size_t i = 1; i < args.size(); ++i) {
    const std::wstring lowered = ToLowerCopy(args[i]);

    if (lowered == L"--help" || lowered == L"-h") {
      result.options.showHelp = true;
      continue;
    }
    if (lowered == L"--version") {
      result.options.showVersion = true;
      continue;
    }
    if (lowered == L"--wizard") {
      result.options.forceWizard = true;
      continue;
    }
    if (lowered == L"--quiet") {
      result.options.quiet = true;
      continue;
    }
    if (lowered == L"--cli" || lowered == L"--cli-internal") {
      sawLegacyCliFlag = true;
      continue;
    }
    if (lowered == L"--force-no-spawn") {
      result.options.skipTerminalSpawn = true;
      continue;
    }
    if (lowered == L"--no-avx512") {
      result.options.noAvx512 = true;
      continue;
    }
    if (lowered == L"--no-avx2") {
      result.options.noAvx2 = true;
      continue;
    }
    if (lowered == L"--mode") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --mode.");
        break;
      }
      auto parsedMode = ParseModeValue(args[++i]);
      if (!parsedMode) {
        AddError(result.errors,
                 L"Invalid value for --mode. Use dynamic, steady, or benchmark.");
        continue;
      }
      result.options.mode = *parsedMode;
      result.options.hasMode = true;
      result.options.runRequested = true;
      continue;
    }
    if (lowered == L"--isa") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --isa.");
        break;
      }
      auto parsedIsa = ParseIsaValue(args[++i]);
      if (!parsedIsa) {
        AddError(result.errors,
                 L"Invalid value for --isa. Use auto, avx512, avx2, scalar, or scalar-sim.");
        continue;
      }
      result.options.workload = *parsedIsa;
      result.options.hasIsa = true;
      continue;
    }
    if (lowered == L"--duration") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --duration.");
        break;
      }
      auto parsed = ParseUint64(args[++i]);
      if (!parsed || *parsed == 0) {
        AddError(result.errors, L"--duration requires a positive integer number of seconds.");
        continue;
      }
      result.options.durationSeconds = *parsed;
      result.options.hasDuration = true;
      result.options.runRequested = true;
      continue;
    }
    if (lowered == L"--max-duration") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --max-duration.");
        break;
      }
      auto parsed = ParseUint64(args[++i]);
      if (!parsed || *parsed == 0) {
        AddError(result.errors,
                 L"--max-duration requires a positive integer number of seconds.");
        continue;
      }
      result.options.maxDurationSeconds = *parsed;
      result.options.hasMaxDuration = true;
      result.options.runRequested = true;
      continue;
    }
    if (lowered == L"--benchmark") {
      result.options.benchmarkRequested = true;
      result.options.mode = 0;
      result.options.hasMode = true;
      result.options.runRequested = true;
      continue;
    }
    if (lowered == L"--verify") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --verify.");
        break;
      }
      result.options.verifyRequested = true;
      result.options.verifyHash = args[++i];
      continue;
    }
    if (lowered == L"--repro") {
      if (i + 2 >= args.size()) {
        AddError(result.errors, L"--repro requires both <seed> and <complexity>.");
        break;
      }
      auto seed = ParseUint64(args[++i]);
      auto complexity = ParsePositiveInt(args[++i]);
      if (!seed || !complexity) {
        AddError(result.errors,
                 L"--repro requires an unsigned 64-bit seed and a positive integer complexity.");
        continue;
      }
      result.options.reproRequested = true;
      result.options.reproSeed = *seed;
      result.options.reproComplexity = *complexity;
      continue;
    }

    AddError(result.errors, L"Unknown option: " + args[i]);
  }

  if (sawLegacyCliFlag && !result.options.runRequested &&
      !result.options.verifyRequested && !result.options.reproRequested) {
    result.options.forceWizard = true;
  }

  if (result.options.showHelp || result.options.showVersion) {
    return result;
  }

  if (result.options.hasDuration && result.options.hasMaxDuration &&
      result.options.durationSeconds != result.options.maxDurationSeconds) {
    AddError(result.errors,
             L"--duration and --max-duration must match when both are provided.");
  }

  if (result.options.verifyRequested && result.options.reproRequested) {
    AddError(result.errors, L"--verify and --repro cannot be combined.");
  }

  if (result.options.verifyRequested &&
      (result.options.forceWizard || result.options.runRequested ||
       result.options.hasMode || result.options.hasDuration ||
       result.options.hasMaxDuration || result.options.hasIsa ||
       result.options.noAvx512 || result.options.noAvx2)) {
    AddError(result.errors,
             L"--verify cannot be combined with run, wizard, or ISA options.");
  }

  if (result.options.reproRequested &&
      (result.options.forceWizard || result.options.benchmarkRequested ||
       result.options.hasDuration || result.options.hasMaxDuration ||
       (result.options.hasMode && result.options.mode == 0))) {
    AddError(result.errors,
             L"--repro cannot be combined with --wizard, --benchmark, or duration options.");
  }

  if (result.options.benchmarkRequested && result.options.hasMode &&
      result.options.mode != 0) {
    AddError(result.errors,
             L"--benchmark cannot be combined with --mode dynamic or --mode steady.");
  }

  if (result.options.hasMode && result.options.mode == 0) {
    if (result.options.hasDuration &&
        result.options.durationSeconds != BENCHMARK_DURATION_SEC) {
      AddError(result.errors,
               L"Benchmark mode always runs for 180 seconds. Remove --duration or set it to 180.");
    }
    if (result.options.hasMaxDuration &&
        result.options.maxDurationSeconds != BENCHMARK_DURATION_SEC) {
      AddError(result.errors,
               L"Benchmark mode always runs for 180 seconds. Remove --max-duration or set it to 180.");
    }
  }

  const bool hasPrimaryAction =
      result.options.forceWizard || result.options.verifyRequested ||
      result.options.reproRequested || result.options.runRequested;
  const bool hasOnlyModifiers =
      !hasPrimaryAction &&
      (result.options.hasIsa || result.options.noAvx512 || result.options.noAvx2 ||
       result.options.skipTerminalSpawn || result.options.quiet || sawLegacyCliFlag);

  if (hasOnlyModifiers) {
    AddError(result.errors,
             L"Modifiers require an explicit action. Use --wizard, --mode, --duration, --benchmark, --verify, or --repro.");
  }

  return result;
}

static void ApplyCliDefaults(CliOptions &options) {
  if (options.showHelp || options.showVersion || options.verifyRequested ||
      options.reproRequested) {
    return;
  }

  if (!options.hasMode) {
    options.mode = kDefaultCliMode;
  }

  if (options.mode == 0) {
    if (!options.hasIsa) {
      options.workload = WL_SCALAR_SIM;
      options.hasIsa = true;
    }
  } else if (!options.hasIsa) {
    options.workload = WL_AUTO;
  }
}

static uint64_t GetEffectiveDuration(const CliOptions &options) {
  if (options.mode == 0)
    return BENCHMARK_DURATION_SEC;
  if (options.hasDuration)
    return options.durationSeconds;
  if (options.hasMaxDuration)
    return options.maxDurationSeconds;
  return 0;
}

static std::optional<std::string> ReadInteractiveLine() {
  std::string line;
  if (!std::getline(std::cin, line))
    return std::nullopt;
  return line;
}

static std::optional<int> AskWizardChoice(const char *prompt, int def, int min,
                                          int max) {
  while (true) {
    std::cout << prompt << " [" << def << "]: ";
    auto line = ReadInteractiveLine();
    if (!line)
      return std::nullopt;
    if (line->empty())
      return def;

    try {
      size_t pos = 0;
      int value = std::stoi(*line, &pos);
      if (pos == line->size() && value >= min && value <= max)
        return value;
    } catch (...) {
    }

    std::cout << "Please enter a number between " << min << " and " << max
              << "." << std::endl;
  }
}

static std::optional<std::wstring> AskWizardText(const char *prompt) {
  while (true) {
    std::cout << prompt;
    auto line = ReadInteractiveLine();
    if (!line)
      return std::nullopt;
    if (!line->empty())
      return ToWide(*line);
    std::cout << "Input cannot be empty." << std::endl;
  }
}

static bool RunCliWizard(CliOptions &options) {
  const int defaultModeChoice = ModeToWizardChoice(options.mode);

  std::cout << "\nSelect Mode:\n"
            << "1. Dynamic\n"
            << "2. Steady\n"
            << "3. Benchmark\n"
            << "4. Verify Hash\n";

  auto modeChoice = AskWizardChoice("Mode", defaultModeChoice, 1, 4);
  if (!modeChoice)
    return false;

  if (*modeChoice == 4) {
    auto hash = AskWizardText("Enter hash (SS3-XXXXXXXXXXXXXXXX): ");
    if (!hash)
      return false;
    options.verifyRequested = true;
    options.verifyHash = *hash;
    options.runRequested = false;
    return true;
  }

  options.hasMode = true;
  options.mode = (*modeChoice == 1) ? 2 : (*modeChoice == 2) ? 1 : 0;
  options.runRequested = true;

  std::cout << "\nSelect ISA:\n"
            << "1. Auto\n"
            << "2. AVX-512\n"
            << "3. AVX2\n"
            << "4. Scalar (synthetic)\n"
            << "5. Scalar (realistic)\n";

  int defaultIsaChoice = WorkloadToWizardChoice(options.workload);
  if (options.mode == 0 && !options.hasIsa) {
    defaultIsaChoice = 5;
    std::cout << "Benchmark default is Scalar (realistic) for comparable hashes.\n";
  }
  auto isaChoice = AskWizardChoice("ISA", defaultIsaChoice, 1, 5);
  if (!isaChoice)
    return false;

  options.workload = MapWizardIsaChoice(*isaChoice);
  options.hasIsa = true;
  return true;
}

static void ResetAppState() {
  g_App.running = false;
  g_App.quit = false;
  g_App.mode = kDefaultCliMode;
  g_App.activeCompilers = 0;
  g_App.activeDecomp = 0;
  g_App.loops = 0;
  g_App.ioActive = false;
  g_App.ramActive = false;
  g_App.resetTimer = false;
  g_App.currentPhase = 0;
  g_App.selectedWorkload = WL_AUTO;
  g_App.shaders = 0;
  g_App.errors = 0;
  g_App.elapsed = 0;
  g_App.currentRate = 0;
  for (int i = 0; i < 3; ++i)
    g_App.benchRates[i] = 0;
  g_App.benchWinner = -1;
  g_App.benchComplete = false;
  g_App.autoStopBenchmark = true;
  g_App.maxDuration = 0;
  g_App.SetBenchHash(L"");

  g_Workers.clear();
  g_IOThreads.clear();
  g_Threads.clear();
  g_DynThread.reset();
  g_WdThread.reset();
  g_RAM.terminate = false;
  g_RAM.localShaders = 0;
  g_RAM.lastTick = 0;
  g_RAM.state = WorkerState::Idle;
}

static void InitializeLocaleForCli() {
#ifndef PLATFORM_WINDOWS
  try {
    std::locale::global(std::locale(""));
  } catch (...) {
    std::setlocale(LC_ALL, "");
  }
#endif
}

static void InitializeRuntime(bool quiet) {
  InitializeLocaleForCli();
  ResetAppState();

  g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
  if (!g_App.log.is_open() && !quiet) {
    std::wcerr << L"Warning: failed to open ShaderStress.log for writing." << std::endl;
  }

  g_App.LogRaw(L"--- Session Start (v" + std::wstring(APP_VERSION) + L") ---");
  g_App.LogRaw(L"OS: " + GetRuntimeOsName());
  g_App.LogRaw(L"Architecture: " + GetArchName());
  g_Cpu = GetCpuInfo();
  g_App.LogRaw(L"CPU: " + g_Cpu.brand);
}

static void ApplyRunOptions(const CliOptions &options) {
  g_ForceNoAVX512 = options.noAvx512;
  g_ForceNoAVX2 = options.noAvx2;
  g_App.mode = options.mode;
  g_App.selectedWorkload = NormalizeWorkloadSelection(options.workload);
  g_App.maxDuration = GetEffectiveDuration(options);
}

static void CleanupWorkers() {
  g_App.quit = true;
  g_App.running = false;
  for (auto &worker : g_Workers)
    worker->terminate = true;
  for (auto &worker : g_IOThreads)
    worker->terminate = true;
  g_RAM.terminate = true;
  g_DynThread.reset();
  g_WdThread.reset();
  g_Threads.clear();
}

static void PrintVerifyResult(const std::wstring &hash, const HashResult &result) {
  if (!result.valid) {
    std::cout << "=== INVALID HASH ===" << std::endl;
    std::wcout << L"Hash: " << hash << std::endl;
    return;
  }

  std::cout << "=== VALID HASH ===" << std::endl;
  std::cout << "Version: ShaderStress " << (int)result.versionMajor << "."
            << (int)result.versionMinor << std::endl;
  std::wcout << L"OS: " << GetOsName(result.os) << std::endl;
  std::wcout << L"Arch: " << GetArchNameFromCode(result.arch) << std::endl;
  std::cout << "CPU Hash: " << (int)result.cpuHash << std::endl;
  std::cout << "R0: " << result.r0 << " jobs/s" << std::endl;
  std::cout << "R1: " << result.r1 << " jobs/s" << std::endl;
  std::cout << "R2: " << result.r2 << " jobs/s" << std::endl;
}

static int RunVerifyCommand(const CliOptions &options) {
  HashResult result = ValidateBenchmarkHash(options.verifyHash);
  PrintVerifyResult(options.verifyHash, result);
  return result.valid ? (int)CliExitCode::Success
                      : (int)CliExitCode::VerificationFailed;
}

static int RunReproCommand(const CliOptions &options) {
  InitializeRuntime(options.quiet);
  ApplyRunOptions(options);
  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();

  if (!options.quiet) {
    PrintCliVersion();
    std::wcout << L"CPU: " << g_Cpu.brand << std::endl;
    std::cout << "Seed: " << options.reproSeed << std::endl;
    std::cout << "Complexity: " << options.reproComplexity << std::endl;
    std::wcout << L"ISA: "
               << GetResolvedISAName(g_App.selectedWorkload.load()) << std::endl;
  }

  g_App.Log(L"Repro Mode: seed=" + std::to_wstring(options.reproSeed) +
            L" complexity=" + std::to_wstring(options.reproComplexity));

  StressConfig reproCfg;
  {
    std::lock_guard<std::mutex> lock(g_ConfigMtx);
    reproCfg = g_ActiveConfig;
  }
  SafeRunWorkload(options.reproSeed, options.reproComplexity, reproCfg, 0);
  g_App.Log(L"Repro finished without crash.");

  if (!options.quiet) {
    std::cout << "Repro completed." << std::endl;
  }
  return (int)CliExitCode::Success;
}

static void PrintLiveDashboard() {
  std::cout << "\033[2J\033[H" << std::flush;
  std::wcout << L"ShaderStress " << APP_VERSION << L"\n";
  std::wcout << L"OS: " << GetRuntimeOsName() << L" (" << GetArchName() << L")\n";
  std::wcout << L"Mode: " << GetModeName(g_App.mode.load()) << L"\n";
  std::wcout << L"Active ISA: "
             << GetResolvedISAName(g_App.selectedWorkload.load()) << L"\n";
  std::wcout << L"Jobs Done: " << FmtNum(g_App.shaders.load()) << L"\n\n";
  std::wcout << L"--- Performance ---\n";
  std::wcout << L"Rate (Jobs/s): " << FmtNum(g_App.currentRate.load()) << L"\n";
  std::wcout << L"Time: " << FmtTime(g_App.elapsed.load()) << L"\n";

  if (g_App.mode == 2) {
    std::wcout << L"Phase: " << g_App.currentPhase.load() << L" / 16\n";
    std::wcout << L"Loop: " << g_App.loops.load() << L"\n";
  } else if (g_App.mode == 0) {
    std::wcout << L"\n--- Benchmark Rounds ---\n";
    std::wcout << L"1st Minute: "
               << (g_App.benchRates[0] > 0 ? FmtNum(g_App.benchRates[0].load())
                                          : L"-")
               << L"\n";
    std::wcout << L"2nd Minute: "
               << (g_App.benchRates[1] > 0 ? FmtNum(g_App.benchRates[1].load())
                                          : L"-")
               << L"\n";
    std::wcout << L"3rd Minute: "
               << (g_App.benchRates[2] > 0 ? FmtNum(g_App.benchRates[2].load())
                                          : L"-")
               << L"\n";

    std::wstring hash = g_App.GetBenchHash();
    if (!hash.empty()) {
      std::wcout << L"Hash: " << hash << L" (v" << APP_VERSION << L")\n";
    }

    if (g_App.benchComplete) {
      std::wcout << L"WINNER: Interval " << (g_App.benchWinner.load() + 1)
                 << L"\n";
    }
  }

  std::wcout << L"\n--- Stress Status ---\n";
  std::wcout << L"Workers: "
             << (g_App.activeCompilers.load() + g_App.activeDecomp.load())
             << L"\n";
  std::wcout << L"Sim Compilers: " << g_App.activeCompilers.load() << L"\n";
  std::wcout << L"Decompressors: " << g_App.activeDecomp.load() << L"\n";
  std::wcout << L"RAM Thread: " << (g_App.ramActive ? L"ACTIVE" : L"Idle")
             << L"\n";
  std::wcout << L"I/O Threads: " << (g_App.ioActive ? L"ACTIVE" : L"Idle")
             << L"\n";

  if (g_App.errors > 0) {
    std::wcout << L"\nErrors: " << FmtNum(g_App.errors.load()) << L" !!!\n";
  } else {
    std::wcout << L"\nErrors: 0\n";
  }

  std::wcout << L"\n[Press Ctrl+C to abort]" << std::flush;
}

static void WriteDashboardField(int row, int col, const std::wstring &value) {
  std::cout << "\033[" << row << ';' << col << "H";
  std::wcout << value;
  std::cout << "\033[K";
}

static CliDashboardLayout RenderCompactDashboardFrame() {
  CliDashboardLayout layout;
  layout.benchmark = g_App.mode == 0;

  std::cout << "\033[2J\033[H\033[?25l";
  std::wcout << L"ShaderStress " << APP_VERSION << L"\n";
  std::wcout << L"OS: " << GetRuntimeOsName() << L" (" << GetArchName() << L")\n";
  std::wcout << L"Mode: " << GetModeName(g_App.mode.load()) << L"\n";
  std::wcout << L"Active ISA: "
             << GetResolvedISAName(g_App.selectedWorkload.load()) << L"\n";
  std::wcout << L"Jobs Done: \n\n";
  std::wcout << L"--- Performance ---\n";
  std::wcout << L"Rate (Jobs/s): \n";
  std::wcout << L"Time: \n";

  if (layout.benchmark) {
    std::wcout << L"\n--- Benchmark Rounds ---\n";
    std::wcout << L"1st Minute: \n";
    std::wcout << L"2nd Minute: \n";
    std::wcout << L"3rd Minute: \n";
    std::wcout << L"Hash: \n";
    std::wcout << L"Winner: \n\n";
    std::wcout << L"--- Stress Status ---\n";
    std::wcout << L"Workers: \n";
    std::wcout << L"Sim Compilers: \n";
    std::wcout << L"Decompressors: \n";
    std::wcout << L"RAM Thread: \n";
    std::wcout << L"I/O Threads: \n";
    std::wcout << L"Errors: \n\n";
    std::wcout << L"[Press Ctrl+C to abort]";
    layout.finalLine = 25;
  } else {
    std::wcout << L"Phase: \n";
    std::wcout << L"Loop: \n\n";
    std::wcout << L"--- Stress Status ---\n";
    std::wcout << L"Workers: \n";
    std::wcout << L"Sim Compilers: \n";
    std::wcout << L"Decompressors: \n";
    std::wcout << L"RAM Thread: \n";
    std::wcout << L"I/O Threads: \n";
    std::wcout << L"Errors: \n\n";
    std::wcout << L"[Press Ctrl+C to abort]";
    layout.finalLine = 20;
  }

  std::wcout.flush();
  return layout;
}

static void UpdateCompactDashboard(const CliDashboardLayout &layout) {
  WriteDashboardField(5, 12, FmtNum(g_App.shaders.load()));
  WriteDashboardField(8, 16, FmtNum(g_App.currentRate.load()));
  WriteDashboardField(9, 7, FmtTime(g_App.elapsed.load()));

  if (layout.benchmark) {
    WriteDashboardField(12, 13,
                        g_App.benchRates[0] > 0 ? FmtNum(g_App.benchRates[0].load())
                                               : L"-");
    WriteDashboardField(13, 13,
                        g_App.benchRates[1] > 0 ? FmtNum(g_App.benchRates[1].load())
                                               : L"-");
    WriteDashboardField(14, 13,
                        g_App.benchRates[2] > 0 ? FmtNum(g_App.benchRates[2].load())
                                               : L"-");

    std::wstring hash = g_App.GetBenchHash();
    WriteDashboardField(15, 7,
                        !hash.empty() ? hash + L" (v" + APP_VERSION + L')' : L"");

    WriteDashboardField(16, 9,
                        g_App.benchComplete ? (L"Interval " + std::to_wstring(g_App.benchWinner.load() + 1))
                                            : L"");

    WriteDashboardField(19, 10,
                        std::to_wstring(g_App.activeCompilers.load() +
                                        g_App.activeDecomp.load()));
    WriteDashboardField(20, 16,
                        std::to_wstring(g_App.activeCompilers.load()));
    WriteDashboardField(21, 16,
                        std::to_wstring(g_App.activeDecomp.load()));
    WriteDashboardField(22, 13, g_App.ramActive ? L"ACTIVE" : L"Idle");
    WriteDashboardField(23, 14, g_App.ioActive ? L"ACTIVE" : L"Idle");
    WriteDashboardField(24, 9,
                        g_App.errors > 0 ? FmtNum(g_App.errors.load()) + L" !!!"
                                         : L"0");
  } else {
    WriteDashboardField(10, 8,
                        g_App.mode == 2 ? (std::to_wstring(g_App.currentPhase.load()) + L" / 16")
                                        : L"-");
    WriteDashboardField(11, 7,
                        g_App.mode == 2 ? std::to_wstring(g_App.loops.load()) : L"-");
    WriteDashboardField(14, 10,
                        std::to_wstring(g_App.activeCompilers.load() +
                                        g_App.activeDecomp.load()));
    WriteDashboardField(15, 16,
                        std::to_wstring(g_App.activeCompilers.load()));
    WriteDashboardField(16, 16,
                        std::to_wstring(g_App.activeDecomp.load()));
    WriteDashboardField(17, 13, g_App.ramActive ? L"ACTIVE" : L"Idle");
    WriteDashboardField(18, 14, g_App.ioActive ? L"ACTIVE" : L"Idle");
    WriteDashboardField(19, 9,
                        g_App.errors > 0 ? FmtNum(g_App.errors.load()) + L" !!!"
                                         : L"0");
  }

  std::wcout.flush();
}

static void PrintFinalResults() {
  std::cout << "\n=== Final Results ===\n";
  std::cout << "Total Jobs: " << (unsigned long long)g_App.shaders.load()
            << "\n";
  std::cout << "Avg Rate: " << (unsigned long long)g_App.currentRate.load()
            << " jobs/s\n";
  std::cout << "Errors: " << (unsigned long long)g_App.errors.load() << "\n";

  if (g_App.mode == 0) {
    std::wstring finalHash = g_App.GetBenchHash();
    if (!finalHash.empty()) {
      std::wcout << L"Benchmark Hash: " << finalHash << L"\n";
    }
  }
}

static int RunStressCommand(const CliOptions &options,
                            const CliEnvironment &environment) {
  InitializeRuntime(options.quiet);
  ApplyRunOptions(options);

  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();

  int cpu = std::thread::hardware_concurrency();
  if (cpu == 0)
    cpu = 4;
  for (int i = 0; i < cpu; ++i)
    g_Workers.push_back(std::make_unique<Worker>());

  if (!options.quiet) {
    PrintCliVersion();
    std::wcout << L"CPU: " << g_Cpu.brand << std::endl;
    std::wcout << L"Mode: " << GetModeName(g_App.mode.load()) << std::endl;
    std::wcout << L"ISA: "
               << GetResolvedISAName(g_App.selectedWorkload.load()) << std::endl;
    if (g_App.maxDuration > 0) {
      std::cout << "Duration: " << (unsigned long long)g_App.maxDuration.load()
                << "s" << std::endl;
    }
    std::cout << "Starting stress test with " << cpu << " threads..."
              << std::endl;
  }

#ifdef PLATFORM_WINDOWS
  g_WindowsInterrupted = false;
  SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#endif

  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);

  g_App.running = true;
  if (g_App.mode == 0) {
    SetWork(cpu, 0, false, false);
  } else if (g_App.mode == 2) {
    g_DynThread = std::make_unique<ThreadWrapper>();
    g_DynThread->t = std::thread(DynamicLoop);
  } else {
    int decomp = std::min(4, std::max(1, cpu / 2));
    int comp = std::max(0, cpu - decomp);
    SetWork(comp, decomp, true, true);
  }

  const bool showLiveDashboard = !options.quiet && environment.stdoutTty;
  CliDashboardLayout dashboardLayout{};
  if (showLiveDashboard) {
    dashboardLayout = RenderCompactDashboardFrame();
    UpdateCompactDashboard(dashboardLayout);
  }

  while (!g_App.quit && !WasInterrupted()) {
    std::this_thread::sleep_for(200ms);
    if (showLiveDashboard) {
      UpdateCompactDashboard(dashboardLayout);
    }
  }

  if (showLiveDashboard) {
    std::cout << "\033[" << (dashboardLayout.finalLine + 1)
              << ";1H\033[?25h" << std::flush;
  }

  CleanupWorkers();

#ifdef PLATFORM_WINDOWS
  SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
#endif

  if (WasInterrupted()) {
    std::cout << "\nInterrupted. Stopping...\n";
  }

  PrintFinalResults();
  return WasInterrupted() ? (int)CliExitCode::Interrupted
                          : (int)CliExitCode::Success;
}

static int RunCliCommand(CliOptions options, const CliEnvironment &environment,
                         bool implicitWizard) {
  if (options.showHelp) {
    PrintCliHelp();
    return (int)CliExitCode::Success;
  }
  if (options.showVersion) {
    PrintCliVersion();
    return (int)CliExitCode::Success;
  }

  const bool needsWizard = options.forceWizard || implicitWizard;
  if (needsWizard) {
    if (!environment.canPrompt) {
      std::wcerr << L"Interactive CLI requires a real terminal for both input and output.\n";
      std::wcerr << L"Use --wizard from a terminal, or run a non-interactive command such as --help or --mode.\n";
      return (int)CliExitCode::EnvironmentError;
    }
    ApplyCliDefaults(options);
    if (!RunCliWizard(options)) {
      std::wcerr << L"Interactive CLI aborted because input closed unexpectedly.\n";
      return (int)CliExitCode::EnvironmentError;
    }
  }

  ApplyCliDefaults(options);

  if (options.verifyRequested) {
    return RunVerifyCommand(options);
  }
  if (options.reproRequested) {
    return RunReproCommand(options);
  }
  if (options.runRequested || needsWizard) {
    return RunStressCommand(options, environment);
  }

  if (environment.canPrompt) {
    std::wcerr << L"No command was selected. Use --wizard or run without redirection from a terminal.\n";
  } else {
    std::wcerr << L"No command was selected. Use --help to see available commands.\n";
  }
  return (int)CliExitCode::EnvironmentError;
}

#ifdef PLATFORM_WINDOWS
static WindowsHandleState QueryWindowsHandle(DWORD stdId) {
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

static CliEnvironment QueryWindowsEnvironment() {
  WindowsHandleState stdinState = QueryWindowsHandle(STD_INPUT_HANDLE);
  WindowsHandleState stdoutState = QueryWindowsHandle(STD_OUTPUT_HANDLE);
  WindowsHandleState stderrState = QueryWindowsHandle(STD_ERROR_HANDLE);

  CliEnvironment env;
  env.stdinTty = stdinState.console;
  env.stdoutTty = stdoutState.console;
  env.stderrTty = stderrState.console;
  env.canPrompt = stdinState.console && stdoutState.console;
  env.hasUsableOutput = stdoutState.console || stdoutState.redirected ||
                        stderrState.console || stderrState.redirected;
  env.launchedFromTerminal = stdinState.console || stdinState.redirected ||
                             stdoutState.console || stdoutState.redirected ||
                             stderrState.console || stderrState.redirected;
  return env;
}

static bool IsWindowsCliLauncherActive() {
  wchar_t value[8] = {};
  return GetEnvironmentVariableW(L"SHADERSTRESS_CLI_LAUNCHER", value,
                                 static_cast<DWORD>(std::size(value))) > 0;
}

static std::vector<std::wstring> GetWindowsArgs() {
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

static void ConfigureWindowsConsoleForCli();

static bool BindHandleToFd(HANDLE handle, int targetFd, int openFlags) {
  HANDLE dupHandle = INVALID_HANDLE_VALUE;
  if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
                       &dupHandle, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
    return false;
  }

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

static void PrepareStreamBuffers() {
  clearerr(stdin);
  std::cin.clear();
  std::wcin.clear();
  std::cout.clear();
  std::cerr.clear();
  std::wcout.clear();
  std::wcerr.clear();
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
}

static CliEnvironment PrepareWindowsCliEnvironment(bool requireInput) {
  WindowsHandleState originalIn = QueryWindowsHandle(STD_INPUT_HANDLE);
  WindowsHandleState originalOut = QueryWindowsHandle(STD_OUTPUT_HANDLE);
  WindowsHandleState originalErr = QueryWindowsHandle(STD_ERROR_HANDLE);

  const bool attachedConsole = AttachConsole(ATTACH_PARENT_PROCESS) != 0;
  FILE *filePtr = nullptr;

  if (attachedConsole && !originalOut.redirected) {
    freopen_s(&filePtr, "CONOUT$", "w", stdout);
  } else if (originalOut.redirected) {
    BindHandleToFd(originalOut.handle, 1, _O_TEXT);
  }

  if (attachedConsole && !originalErr.redirected) {
    freopen_s(&filePtr, "CONOUT$", "w", stderr);
  } else if (originalErr.redirected) {
    BindHandleToFd(originalErr.handle, 2, _O_TEXT);
  }

  if (requireInput) {
    if (originalIn.redirected) {
      BindHandleToFd(originalIn.handle, 0, _O_TEXT);
    } else if (attachedConsole) {
      freopen_s(&filePtr, "CONIN$", "r", stdin);
    }
  }

  PrepareStreamBuffers();
  ConfigureWindowsConsoleForCli();

  return QueryWindowsEnvironment();
}

static void ConfigureWindowsConsoleForCli() {
  SetConsoleCP(CP_UTF8);
  SetConsoleOutputCP(CP_UTF8);
  std::cin.clear();
  std::wcin.clear();
  std::cout.clear();
  std::cerr.clear();
  std::wcout.clear();
  std::wcerr.clear();

  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (GetConsoleMode(hOut, &mode)) {
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
}

static int PrintWindowsCliRedirectNotice() {
  const std::wstring message =
  L"Windows command-line usage is provided by ShaderStress.com.\n\n"
  L"Run ShaderStress.com --help for usage.";

  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    FILE *fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    std::wcerr << message << std::endl;
    FreeConsole();
  } else {
    MessageBoxW(nullptr, message.c_str(), L"Use ShaderStress.com",
                MB_OK | MB_ICONINFORMATION);
  }

  return (int)CliExitCode::InvalidArguments;
}

static int RunWindowsGui() {
  HINSTANCE inst = GetModuleHandleW(nullptr);
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  g_Scale = GetDpiForSystem() / 96.0f;

  InitializeRuntime(false);
  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();

  int cpu = std::thread::hardware_concurrency();
  if (cpu == 0)
    cpu = 4;
  for (int i = 0; i < cpu; ++i)
    g_Workers.push_back(std::make_unique<Worker>());

  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);

  WNDCLASSW wc{0,       WndProc, 0,     0, inst, nullptr,
               LoadCursor(0, IDC_ARROW), nullptr, nullptr, L"SST"};
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
  RegisterClassW(&wc);
  InitGDI();

  RECT rc = {0, 0, S(760), S(710)};
  DWORD style =
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
  AdjustWindowRect(&rc, style, FALSE);
  int windowWidth = rc.right - rc.left;
  int windowHeight = rc.bottom - rc.top;

  g_MainWindow = CreateWindowW(
      L"SST", L"Shader Stress", style,
      (GetSystemMetrics(SM_CXSCREEN) - windowWidth) / 2,
      (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2, windowWidth,
      windowHeight, 0, 0, inst, 0);

  BOOL dark = TRUE;
  DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark,
                        sizeof(dark));
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

#ifdef _MSC_VER
#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "dwmapi")
#pragma comment(lib, "shcore")
#pragma comment(lib, "shell32")
#pragma comment(lib, "dbghelp")
#endif

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
  std::vector<std::wstring> args = GetWindowsArgs();
  const bool launcherActive = IsWindowsCliLauncherActive();

  if (!launcherActive) {
    if (args.size() > 1) {
      return PrintWindowsCliRedirectNotice();
    }
    return RunWindowsGui();
  }

  CliParseResult parsed = ParseCliArgs(args);
  const bool hadArgs = args.size() > 1;
  CliEnvironment runtimeEnv =
      PrepareWindowsCliEnvironment(!hadArgs || parsed.options.forceWizard);
  const bool implicitWizard = !hadArgs;

  if (!parsed.errors.empty()) {
    for (const auto &error : parsed.errors)
      std::wcerr << L"Error: " << error << std::endl;
    std::wcerr << L"Use --help to see the supported command line options." << std::endl;
    return (int)CliExitCode::InvalidArguments;
  }

  return RunCliCommand(parsed.options, runtimeEnv, implicitWizard);
}

#else

int main(int argc, char *argv[]) {
  std::vector<std::wstring> args;
  args.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i)
    args.push_back(ToWide(argv[i]));

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

#if defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)
  if (needsInteractiveTerminal && !env.canPrompt && !parsed.options.skipTerminalSpawn) {
    if (TrySpawnTerminal(argc, argv)) {
      return 0;
    }
    ShowTerminalRequiredError();
    return (int)CliExitCode::EnvironmentError;
  }
#endif

  if (!parsed.errors.empty()) {
    for (const auto &error : parsed.errors)
      std::wcerr << L"Error: " << error << std::endl;
    std::wcerr << L"Use --help to see the supported command line options." << std::endl;
    return (int)CliExitCode::InvalidArguments;
  }

  InstallSignalHandlers();
  InstallCrashHandlers();
  return RunCliCommand(parsed.options, env, implicitWizard);
}

#endif