// CliRun.cpp - Runtime bring-up, CLI commands and the live terminal dashboard
#include "engine/AuxStress.h"
#include "app/Cli.h"
#include "engine/Scheduler.h"
#include "core/Topology.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"
#include <clocale>
#include <csignal>
#include <cstring>

using namespace std::chrono_literals;

// --- Interrupt handling ------------------------------------------------------
namespace {
std::atomic<bool> s_interrupted{false};

#ifdef PLATFORM_WINDOWS
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
  switch (ctrlType) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    s_interrupted = true;
    g_App.quit = true;
    g_App.running = false;
    return TRUE;
  default:
    return FALSE;
  }
}
#else
void SignalHandler(int) {
  s_interrupted = true;
  g_App.quit = true;
  g_App.running = false;
}
#endif
} // namespace

bool WasInterrupted() { return s_interrupted.load(); }
void ResetInterrupted() { s_interrupted = false; }

void InstallInterruptHandlers() {
#ifdef PLATFORM_WINDOWS
  SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#else
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SignalHandler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
#endif
}

void RemoveInterruptHandlers() {
#ifdef PLATFORM_WINDOWS
  SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
#endif
}

// --- Runtime bring-up ---------------------------------------------------------
static void ResetAppState() {
  g_App.running = false;
  g_App.quit = false;
  g_App.mode = MODE_DYNAMIC;
  g_App.assignment = 0;
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
  g_App.cycleCore = -1;
  g_App.SetBenchHash(L"");
  g_Workers.clear();
  g_Threads.clear();
  g_DynThread.reset();
  g_WdThread.reset();
}

void InitializeRuntime(bool quiet) {
#ifndef PLATFORM_WINDOWS
  std::setlocale(LC_ALL, "");
#endif
  ResetAppState();
  g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
  if (!g_App.log.is_open() && !quiet)
    std::cerr << "Warning: failed to open ShaderStress.log for writing." << '\n';

  g_App.LogRaw(L"--- Session Start (v" + std::wstring(APP_VERSION) + L") ---");
#if defined(__clang__)
  g_App.LogRaw(L"Compiler: Clang " + ToWide(__clang_version__));
#elif defined(_MSC_VER)
  g_App.LogRaw(L"Compiler: MSVC " + std::to_wstring(_MSC_FULL_VER));
#endif
#ifdef SHADERSTRESS_BUILD_LABEL
  g_App.LogRaw(L"Build: " + ToWide(SHADERSTRESS_BUILD_LABEL));
#endif
  g_App.LogRaw(L"OS: " + GetRuntimeOsName());
  g_App.LogRaw(L"Architecture: " + GetArchName());
  g_Cpu = GetCpuInfo();
  g_App.LogRaw(L"CPU: " + g_Cpu.brand + L" (family " + std::to_wstring(g_Cpu.family) +
               L", model " + std::to_wstring(g_Cpu.model) + L", AVX2 " +
               (g_Cpu.hasAVX2 ? L"yes" : L"no") + L", FMA " + (g_Cpu.hasFMA ? L"yes" : L"no") +
               L", AVX-512F " + (g_Cpu.hasAVX512F ? L"yes" : L"no") + L")");
  g_App.LogRaw(L"Kernel config: buffer " + std::to_wstring(SYNTH_BUF_KIB) + L" KiB/thread, " +
               std::to_wstring(SYNTH_ROUNDS) + L" butterfly rounds per load, " +
               ToWide(SYNTH_FAR_FILL_DESC) + L", realistic sim " + REALISTIC_SIM_VERSION);
  InstallCrashHandlers();
#ifdef PLATFORM_WINDOWS
  RequestHighPerformance();
#endif
  StartPowerMeasurement();
}

void CleanupWorkers() {
  g_App.quit = true;
  g_App.running = false;
  g_DynThread.reset();
  StopWorkerPool();
  g_WdThread.reset();
#ifdef PLATFORM_WINDOWS
  ReleaseHighPerformance();
#endif
  ShutdownPowerMeasurement();
}

static void ApplyRunOptions(const CliOptions &options) {
  g_ForceNoAVX512 = options.noAvx512;
  g_ForceNoAVX2 = options.noAvx2;
  g_RunOpts = options.run;
  g_App.mode = options.mode;
  g_App.selectedWorkload = NormalizeWorkloadSelection(options.workload);
  g_App.maxDuration = CliRunDurationSeconds(options);
}

// --- Simple commands ----------------------------------------------------------
static int RunPerfStatsCommand() {
  g_Cpu = GetCpuInfo();
  SetFpuFlushMode();
  RunPerfStats();
  return (int)CliExitCode::Success;
}

static int RunHashRoundtripCommand() {
  const uint64_t r0 = 12345, r1 = 23456, r2 = 34567;
  std::wstring hash = GenerateBenchmarkHash(r0, r1, r2);
  HashResult decoded = ValidateBenchmarkHash(hash);
  if (!decoded.valid || decoded.r0 != r0 || decoded.r1 != r1 || decoded.r2 != r2) {
    std::cerr << "Hash roundtrip FAILED: " << ToNarrow(hash) << '\n';
    return (int)CliExitCode::InvalidArguments;
  }
  std::cout << "Hash roundtrip OK: " << ToNarrow(hash) << '\n';
  return (int)CliExitCode::Success;
}

static int RunVerifyCommand(const CliOptions &options) {
  HashResult result = ValidateBenchmarkHash(options.verifyHash);
  if (!result.valid) {
    std::cout << "=== INVALID HASH ===\nHash: " << ToNarrow(options.verifyHash) << '\n';
    return (int)CliExitCode::VerificationFailed;
  }
  std::cout << "=== VALID HASH ===\n"
            << "Version: ShaderStress " << (int)result.versionMajor << "."
            << (int)result.versionMinor << '\n'
            << "OS: " << ToNarrow(GetOsName(result.os)) << '\n'
            << "Arch: " << ToNarrow(GetArchNameFromCode(result.arch)) << '\n'
            << "CPU Hash: " << (int)result.cpuHash << '\n'
            << "R0: " << result.r0 << " jobs/s\nR1: " << result.r1 << " jobs/s\nR2: "
            << result.r2 << " jobs/s\n";
  return (int)CliExitCode::Success;
}

static int RunReproCommand(const CliOptions &options) {
  InitializeRuntime(options.quiet);
  ApplyRunOptions(options);
  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();
  const WorkloadType type = ResolveSelectedWorkload(g_App.selectedWorkload.load());
  if (!options.quiet) {
    PrintCliVersion();
    std::cout << "CPU: " << ToNarrow(g_Cpu.brand) << '\n'
              << "Seed: " << options.reproSeed << '\n'
              << "Complexity: " << options.reproComplexity << '\n'
              << "ISA: " << ToNarrow(GetResolvedISAName(type)) << '\n';
  }
  ResetInterrupted();
  InstallInterruptHandlers();
  g_App.Log(L"Repro Mode: seed=" + std::to_wstring(options.reproSeed) +
            L" complexity=" + std::to_wstring(options.reproComplexity));

  // Same job twice on this thread; any difference is a hardware fault.
  BeginJob(type, options.reproSeed, options.reproComplexity);
  uint64_t a = RunComputeWorkload(type, options.reproSeed, options.reproComplexity);
  BeginJob(type, options.reproSeed, options.reproComplexity);
  uint64_t b = WasInterrupted() ? a
                                : RunComputeWorkload(type, options.reproSeed,
                                                     options.reproComplexity);
  const bool match = a == b;
  g_App.Log(L"Repro result " + FmtHex64(a) + (match ? L" (re-run matches)"
                                                    : L" MISMATCH re-run " + FmtHex64(b)));
  CleanupWorkers();
  RemoveInterruptHandlers();
  if (!options.quiet) {
    std::cout << "Result: " << ToNarrow(FmtHex64(a)) << '\n';
    std::cout << (match ? "Repro completed: re-run matches." : "Repro FAILED: re-run differs!")
              << std::endl;
  }
  if (WasInterrupted()) return (int)CliExitCode::Interrupted;
  return match ? (int)CliExitCode::Success : (int)CliExitCode::HardwareErrors;
}

// --- Live dashboard -----------------------------------------------------------
static std::vector<std::string> BuildDashboardLines() {
  std::vector<std::string> L;
  const int mode = g_App.mode.load();
  L.push_back("ShaderStress " + ToNarrow(APP_VERSION) + " | " + ToNarrow(GetRuntimeOsName()) +
              " (" + ToNarrow(GetArchName()) + ") | " + ToNarrow(g_Cpu.brand));
  L.push_back("Mode: " + ToNarrow(GetModeName(mode)) + " | ISA: " +
              ToNarrow(GetResolvedISAName(g_App.selectedWorkload.load())) + " | Threads: " +
              std::to_string(g_Workers.size()) + " (" + ToNarrow(TopologySummary()) + ")");
  std::string perf = "Time: " + ToNarrow(FmtTime(g_App.elapsed.load())) + " | Jobs: " +
                     ToNarrow(FmtNum(g_App.shaders.load())) + " | Rate: " +
                     ToNarrow(FmtNum(g_App.currentRate.load())) + " jobs/s";
  std::wstring power = FormatPowerReadout(SampleCpuPower());
  if (!power.empty()) perf += " | Power: " + ToNarrow(power);
  L.push_back(perf);

  if (mode == MODE_DYNAMIC) {
    int ph = g_App.currentPhase.load();
    L.push_back("Phase: " + std::to_string(ph) + " / " + std::to_string(DYNAMIC_PHASES) + " (" +
                ToNarrow(DynamicPhaseName(ph)) + ") | Loop: " +
                std::to_string(g_App.loops.load()));
  } else if (mode == MODE_CORE_CYCLE) {
    int core = g_App.cycleCore.load();
    int64_t left = (int64_t)g_App.cycleNextTick.load() - (int64_t)GetTick();
    L.push_back("Core: " + std::to_string(core + 1) + " / " +
                std::to_string(CoreCycleCoreCount()) + " | next in " +
                std::to_string(std::max<int64_t>(0, left / 1000)) + " s | Loop: " +
                std::to_string(g_App.loops.load()));
  } else if (mode == MODE_BENCHMARK) {
    auto rate = [](int i) {
      uint64_t r = g_App.benchRates[i].load();
      return r > 0 ? ToNarrow(FmtNum(r)) : std::string("-");
    };
    L.push_back("Minutes: " + rate(0) + " / " + rate(1) + " / " + rate(2) +
                (g_App.benchComplete ? " | Winner: " + std::to_string(g_App.benchWinner + 1)
                                     : std::string()));
    std::wstring hash = g_App.GetBenchHash();
    L.push_back("Hash: " + (hash.empty() ? std::string("-") : ToNarrow(hash)));
  }

  AuxStatus aux = GetAuxStatus();
  std::string ram = g_App.ramActive ? "ACTIVE" : "idle";
  if (aux.ramBytes) ram += " (" + ToNarrow(FmtBytes(aux.ramBytes)) + ", " +
                           std::to_string(aux.ramPasses) + " passes)";
  const WorkAssignment wa = WorkAssignment::Unpack(g_App.assignment.load());
  if (wa.ram) ram += " [" + std::to_string(wa.ram) + " worker(s)]";
  L.push_back("Workers: compute " + std::to_string(g_App.activeCompilers.load()) +
              ", decompress " + std::to_string(g_App.activeDecomp.load()) + " | RAM: " + ram +
              " | I/O: " + (g_App.ioActive ? "ACTIVE (stream worker)" : "idle") + " | " +
              std::to_string(wa.Active()) + "/" + std::to_string(g_Workers.size()) + " slots");
  VerifyStats v = GetVerifyStats();
  L.push_back("Verified: " + std::to_string(v.pairsMatched) + " job pairs, " +
              std::to_string(v.goldenChecks) + " golden, " + std::to_string(v.decompPasses) +
              " decompress passes, RAM " + ToNarrow(FmtBytes(v.ramBytesVerified)) + ", I/O " +
              ToNarrow(FmtBytes(v.ioBytesVerified)));
  uint64_t errors = g_App.errors.load();
  std::string err = "Errors: " + std::to_string(errors) + " (CPU " +
                    std::to_string(v.cpuErrors) + ", RAM " + std::to_string(v.ramErrors) +
                    ", I/O " + std::to_string(v.ioErrors) + ")";
  if (errors > 0) err += " !!!";
  L.push_back(err);
  std::wstring cpus = FormatErrorCpus(4);
  if (!cpus.empty()) L.push_back("Error CPUs: " + ToNarrow(cpus));
  L.push_back("");
  L.push_back("[Press Ctrl+C to abort]");
  return L;
}

static void DrawDashboard() {
  std::string frame = "\033[H";
  for (const auto &line : BuildDashboardLines())
    frame += line + "\033[K\n";
  frame += "\033[J";
  std::cout << frame << std::flush;
}

static void PrintFinalResults(const CliOptions &options) {
  VerifyStats v = GetVerifyStats();
  std::cout << "\n=== Final Results ===\n"
            << "Total Jobs: " << (unsigned long long)g_App.shaders.load() << "\n"
            << "Avg Rate: " << (unsigned long long)(g_App.shaders.load() / std::max<uint64_t>(1, g_App.elapsed.load()))
            << " jobs/s (whole run; the live rate is a sliding window)\n";
  double cpuW = SampleCpuPackagePower();
  if (cpuW > 0) {
    std::cout << "CPU Package Power: " << (int)cpuW << " W\n";
    g_App.Log(L"Final CPU Package Power: " + std::to_wstring((int)cpuW) + L" W");
  }
  std::cout << "Verified: " << v.pairsMatched << " job pairs, " << v.goldenChecks
            << " golden checks, " << v.decompPasses << " decompression passes, RAM "
            << ToNarrow(FmtBytes(v.ramBytesVerified)) << ", I/O "
            << ToNarrow(FmtBytes(v.ioBytesVerified)) << "\n";
  std::cout << "Errors: " << (unsigned long long)g_App.errors.load() << " (CPU " << v.cpuErrors
            << ", RAM " << v.ramErrors << ", I/O " << v.ioErrors << ")\n";
  std::wstring cpus = FormatErrorCpus(16);
  if (!cpus.empty()) std::cout << "Error CPUs: " << ToNarrow(cpus) << "\n";
  if (g_App.mode == MODE_BENCHMARK && !options.powerWindowSeconds) {
    std::wstring finalHash = g_App.GetBenchHash();
    if (!finalHash.empty()) std::cout << "Benchmark Hash: " << ToNarrow(finalHash) << "\n";
  }
}

static int RunStressCommand(const CliOptions &options, const CliEnvironment &environment) {
  InitializeRuntime(options.quiet);
  ApplyRunOptions(options);
  if (options.powerWindowSeconds) {
    g_App.Log(L"Power measurement: benchmark job mix, compute workers only, no decompression/RAM/I/O; "
              L"limit " + std::to_wstring(options.powerWindowSeconds) + L" s; no benchmark score/hash.");
  }
  SetFpuFlushMode();
  InitGoldenValues();
  DetectBestConfig();
  ResetVerification();
  const int cpu = CreateWorkerPool();

  if (!options.quiet) {
    PrintCliVersion();
    std::cout << "CPU: " << ToNarrow(g_Cpu.brand) << '\n'
              << "Mode: " << ToNarrow(GetModeName(g_App.mode.load())) << '\n'
              << "ISA: " << ToNarrow(GetResolvedISAName(g_App.selectedWorkload.load())) << '\n';
    if (g_App.maxDuration > 0)
      std::cout << "Duration: " << (unsigned long long)g_App.maxDuration.load() << "s\n";
    std::cout << "Starting stress test with " << cpu << " threads...\n";
  }

  ResetInterrupted();
  InstallInterruptHandlers(); // before any thread starts

  g_WdThread = std::make_unique<ThreadWrapper>();
  g_WdThread->t = std::thread(Watchdog);
  g_App.running = true;
  StartModeWork();

  const bool showLiveDashboard = !options.quiet && environment.stdoutTty;
  if (showLiveDashboard) std::cout << "\033[2J\033[?25l";
  while (!g_App.quit && !WasInterrupted()) {
    std::this_thread::sleep_for(250ms); // dashboard refresh cadence
    if (showLiveDashboard) DrawDashboard();
  }
  if (showLiveDashboard) std::cout << "\033[?25h" << std::flush;

  CleanupWorkers();
  RemoveInterruptHandlers();
  if (WasInterrupted()) std::cout << "\nInterrupted. Stopping...\n";
  PrintFinalResults(options);
  if (WasInterrupted()) return (int)CliExitCode::Interrupted;
  return g_App.errors.load() > 0 ? (int)CliExitCode::HardwareErrors : (int)CliExitCode::Success;
}

int RunCliCommand(CliOptions options, const CliEnvironment &environment, bool implicitWizard) {
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
      std::cerr << "Interactive CLI requires a real terminal for both input and output.\n"
                << "Use --wizard from a terminal, or run a non-interactive command such as "
                   "--help or --mode.\n";
      return (int)CliExitCode::EnvironmentError;
    }
    ApplyCliDefaults(options);
    if (!RunCliWizard(options)) {
      std::cerr << "Interactive CLI aborted because input closed unexpectedly.\n";
      return (int)CliExitCode::EnvironmentError;
    }
  }
  ApplyCliDefaults(options);

  if (options.selfTestRequested) {
    g_Cpu = GetCpuInfo();
    SetFpuFlushMode();
    return RunSelfTests() == 0 ? (int)CliExitCode::Success : (int)CliExitCode::TestFailed;
  }
  if (options.hashRoundtripRequested) return RunHashRoundtripCommand();
  if (options.perfStatsRequested) return RunPerfStatsCommand();
  if (options.verifyRequested) return RunVerifyCommand(options);
  if (options.reproRequested) return RunReproCommand(options);
  if (options.runRequested || needsWizard) return RunStressCommand(options, environment);

  std::cerr << (environment.canPrompt
                    ? "No command was selected. Use --wizard or run without redirection from a "
                      "terminal.\n"
                    : "No command was selected. Use --help to see available commands.\n");
  return (int)CliExitCode::EnvironmentError;
}
