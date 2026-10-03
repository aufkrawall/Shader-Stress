// Cli.h - Command-line options, parsing and command entry points
#pragma once
#include "core/Common.h"

enum class CliExitCode : int {
  Success = 0,
  TestFailed = 1,
  InvalidArguments = 2,
  EnvironmentError = 3,
  VerificationFailed = 4,
  HardwareErrors = 5,
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
  bool hashRoundtripRequested = false;
  bool perfStatsRequested = false;
  bool selfTestRequested = false;

  bool hasMode = false;
  bool hasIsa = false;
  bool hasDuration = false;
  bool hasDwell = false;
  bool noAvx512 = false;
  bool noAvx2 = false;
  int mode = MODE_DYNAMIC;
  WorkloadType workload = WL_AUTO;
  uint64_t durationSeconds = 0;
  uint64_t reproSeed = 0;
  int reproComplexity = 0;
  std::wstring verifyHash;
  RunOptions run; // --threads, --no-ram, --no-io, --ram-mb, --io-mb, --dwell
  bool hasRunTuning = false;
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

#ifdef PLATFORM_WINDOWS
constexpr wchar_t kProgramInvocation[] = L"ShaderStress.com";
#else
constexpr wchar_t kProgramInvocation[] = L"./shaderstress";
#endif

std::string ToNarrow(const std::wstring &value);
std::wstring ToWide(const std::string &value);
std::wstring ToLowerCopy(std::wstring value);
std::wstring GetRuntimeOsName();

CliParseResult ParseCliArgs(const std::vector<std::wstring> &args);
void ApplyCliDefaults(CliOptions &options);
void PrintCliHelp();
void PrintCliVersion();
bool RunCliWizard(CliOptions &options);

// Dispatches a parsed command line (wizard, run, repro, verify, ...).
int RunCliCommand(CliOptions options, const CliEnvironment &environment, bool implicitWizard);
// Shared runtime bring-up for CLI and GUI.
void InitializeRuntime(bool quiet);
void CleanupWorkers();

// Interrupt state (set by Ctrl+C / signal handlers).
bool WasInterrupted();
void ResetInterrupted();
void InstallInterruptHandlers();
void RemoveInterruptHandlers();

// In-process unit tests (--self-test). Returns the number of failures.
int RunSelfTests();
