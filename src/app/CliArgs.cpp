// CliArgs.cpp - Command-line parsing, help text and interactive wizard
#include "app/Cli.h"
#include <charconv>
#include <cwctype>
#include <limits>

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t ch) { return (wchar_t)std::towlower(ch); });
  return value;
}

std::wstring ToWide(const std::string &value) {
  return std::wstring(value.begin(), value.end());
}

std::string ToNarrow(const std::wstring &value) {
  return std::string(value.begin(), value.end());
}

std::wstring GetRuntimeOsName() {
#ifdef PLATFORM_WINDOWS
  return L"Windows";
#elif defined(PLATFORM_LINUX)
  return L"Linux";
#else
  return L"macOS";
#endif
}

namespace {
std::optional<uint64_t> ParseUint64(const std::wstring &text) {
  if (text.empty())
    return std::nullopt;
  std::string narrow(text.begin(), text.end());
  uint64_t result = 0;
  auto [ptr, ec] = std::from_chars(narrow.data(), narrow.data() + narrow.size(), result, 10);
  if (ec != std::errc() || ptr != narrow.data() + narrow.size())
    return std::nullopt;
  return result;
}

std::optional<int> ParsePositiveInt(const std::wstring &text) {
  if (text.empty())
    return std::nullopt;
  std::string narrow(text.begin(), text.end());
  long long parsed = 0;
  auto [ptr, ec] = std::from_chars(narrow.data(), narrow.data() + narrow.size(), parsed, 10);
  if (ec != std::errc() || ptr != narrow.data() + narrow.size() || parsed <= 0 ||
      parsed > std::numeric_limits<int>::max())
    return std::nullopt;
  return static_cast<int>(parsed);
}

std::optional<int> ParseModeValue(const std::wstring &text) {
  const std::wstring lowered = ToLowerCopy(text);
  if (lowered == L"dynamic") return MODE_DYNAMIC;
  if (lowered == L"steady") return MODE_STEADY;
  if (lowered == L"benchmark") return MODE_BENCHMARK;
  if (lowered == L"corecycle" || lowered == L"core-cycle" || lowered == L"cycle")
    return MODE_CORE_CYCLE;
  return std::nullopt;
}

std::optional<WorkloadType> ParseIsaValue(const std::wstring &text) {
  const std::wstring lowered = ToLowerCopy(text);
  if (lowered == L"auto") return WL_AUTO;
  if (lowered == L"avx512" || lowered == L"avx-512") return WL_AVX512;
  if (lowered == L"avx2" || lowered == L"avx-2") return WL_AVX2;
  if (lowered == L"scalar" || lowered == L"scalar-synthetic" ||
      lowered == L"scalar_synthetic" || lowered == L"sse2" || lowered == L"neon")
    return WL_SCALAR;
  if (lowered == L"scalar-sim" || lowered == L"scalar_sim" ||
      lowered == L"scalar-realistic" || lowered == L"realistic")
    return WL_SCALAR_SIM;
  return std::nullopt;
}

void AddError(std::vector<std::wstring> &errors, const std::wstring &msg) {
  errors.push_back(msg);
}

// Parses "<flag> <positive int>" into `out`; returns false (and records an
// error) when the value is missing or invalid.
bool TakePositiveInt(const std::vector<std::wstring> &args, size_t &i, const wchar_t *flag,
                     int minValue, int maxValue, int &out,
                     std::vector<std::wstring> &errors) {
  if (i + 1 >= args.size()) {
    AddError(errors, std::wstring(L"Missing value for ") + flag + L".");
    return false;
  }
  auto v = ParsePositiveInt(args[++i]);
  if (!v || *v < minValue || *v > maxValue) {
    AddError(errors, std::wstring(flag) + L" requires an integer between " +
                         std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L".");
    return false;
  }
  out = *v;
  return true;
}
} // namespace

void PrintCliVersion() { std::cout << "ShaderStress " << ToNarrow(APP_VERSION) << '\n'; }

void PrintCliHelp() {
  const std::string inv = ToNarrow(kProgramInvocation);
  PrintCliVersion();
  std::cout << "\nUsage:\n"
            << "  " << inv << "\n"
            << "  " << inv << " --wizard [options]\n"
            << "  " << inv << " --mode <dynamic|steady|benchmark|corecycle> [options]\n"
            << "  " << inv << " --benchmark\n"
            << "  " << inv << " --verify <hash>\n"
            << "  " << inv << " --repro <seed> <complexity> [options]\n";
  std::cout << "\nLaunch behavior:\n";
#ifdef PLATFORM_WINDOWS
  std::cout << "  - No arguments from Explorer or a shortcut open the GUI.\n"
            << "  - Use ShaderStress.com from a terminal to open the interactive CLI wizard.\n"
            << "  - Use ShaderStress.com for explicit Windows CLI commands.\n";
#else
  std::cout << "  - No arguments open the interactive CLI wizard.\n"
            << "  - If launched without a terminal and the wizard is needed,\n"
            << "    ShaderStress will try to spawn one unless --force-no-spawn is used.\n";
#endif
  std::cout
      << "\nModes:\n"
      << "  dynamic     16 rotating load patterns: full load, transients, square waves,\n"
      << "              ramps, RAM/IO mixes and a single-core boost sweep (default).\n"
      << "  steady      Constant full load: compute + decompression + RAM + I/O testers.\n"
      << "  benchmark   Fixed 180 s throughput run with a shareable result hash.\n"
      << "  corecycle   One compute thread per physical core in turn (max single-core\n"
      << "              boost); finds per-core instability such as unstable undervolts.\n"
      << "\nCommands and options:\n"
      << "  --wizard                 Force the interactive CLI wizard.\n"
      << "  --mode <name>            Run without prompts (see Modes).\n"
      << "  --isa <name>             auto, avx512, avx2, scalar (SSE2/NEON), scalar-sim.\n"
      << "  --duration <sec>         Stop after N seconds.\n"
      << "  --max-duration <sec>     Alias of --duration.\n"
      << "  --benchmark              Shortcut for --mode benchmark (180 s, defaults to scalar-sim).\n"
      << "  --threads <n>            Use at most N worker threads (fastest cores first).\n"
      << "  --dwell <sec>            Core-cycle time per core (default 60).\n"
      << "  --no-ram                 Never run the RAM tester.\n"
      << "  --no-io                  Never run the storage tester (no temp file writes).\n"
      << "  --no-decompress          Use compute workers instead of decompression workers.\n"
      << "  --ram-mb <n>             RAM tester size (default 70% of free RAM, max 16 GiB).\n"
      << "  --io-mb <n>              Storage tester file size (default 512).\n"
      << "  --verify <hash>          Decode and validate a benchmark hash.\n"
      << "  --repro <seed> <complexity>\n"
      << "                           Run one job twice and compare (exit 5 on mismatch).\n"
      << "  --self-test              Run the built-in unit tests (fast, no stress).\n"
      << "  --hash-roundtrip         Internal: verify hash encode/decode roundtrip.\n"
      << "  --perf-stats             Single-thread cost and health of every kernel.\n"
      << "  --no-avx512              Disable AVX-512 use.\n"
      << "  --no-avx2                Disable AVX2 use.\n"
      << "  --quiet                  Suppress the live dashboard and startup banner.\n"
      << "  --version                Print version and exit.\n"
      << "  --help                   Print this help text and exit.\n";
#if !defined(PLATFORM_WINDOWS)
  std::cout << "  --force-no-spawn         Do not auto-spawn a terminal for the wizard.\n";
#endif
  std::cout << "\nExit codes:\n"
            << "  0   Success, no errors detected\n"
            << "  1   Self-test failed\n"
            << "  2   Invalid arguments\n"
            << "  3   Environment/setup problem\n"
            << "  4   Hash verification failed\n"
            << "  5   Hardware errors detected (CPU, RAM or I/O verification failed)\n"
            << "  130 Interrupted by Ctrl+C or a termination signal\n";
  std::cout << "\nExamples:\n"
            << "  " << inv << " --wizard\n"
            << "  " << inv << " --mode steady --isa avx2 --duration 600\n"
            << "  " << inv << " --mode corecycle --isa scalar --dwell 120\n"
            << "  " << inv << " --benchmark\n"
            << "  " << inv << " --repro 12345 1000 --isa scalar\n";
}

CliParseResult ParseCliArgs(const std::vector<std::wstring> &args) {
  CliParseResult result;
  CliOptions &o = result.options;
  bool sawLegacyCliFlag = false;

  for (size_t i = 1; i < args.size(); ++i) {
    const std::wstring lowered = ToLowerCopy(args[i]);

    if (lowered == L"--help" || lowered == L"-h") { o.showHelp = true; continue; }
    if (lowered == L"--version") { o.showVersion = true; continue; }
    if (lowered == L"--wizard") { o.forceWizard = true; continue; }
    if (lowered == L"--quiet") { o.quiet = true; continue; }
    if (lowered == L"--cli" || lowered == L"--cli-internal") { sawLegacyCliFlag = true; continue; }
    if (lowered == L"--force-no-spawn") { o.skipTerminalSpawn = true; continue; }
    if (lowered == L"--no-avx512") { o.noAvx512 = true; continue; }
    if (lowered == L"--no-avx2") { o.noAvx2 = true; continue; }
    if (lowered == L"--no-ram") { o.run.noRam = true; o.hasRunTuning = true; continue; }
    if (lowered == L"--no-io") { o.run.noIo = true; o.hasRunTuning = true; continue; }
    if (lowered == L"--no-decompress") { o.run.noDecomp = true; o.hasRunTuning = true; continue; }
    if (lowered == L"--hash-roundtrip") { o.hashRoundtripRequested = true; continue; }
    if (lowered == L"--self-test") { o.selfTestRequested = true; continue; }
    if (lowered == L"--perf-stats") { o.perfStatsRequested = true; o.runRequested = true; continue; }
    if (lowered == L"--mode") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --mode.");
        break;
      }
      auto parsedMode = ParseModeValue(args[++i]);
      if (!parsedMode) {
        AddError(result.errors,
                 L"Invalid value for --mode. Use dynamic, steady, benchmark, or corecycle.");
        continue;
      }
      o.mode = *parsedMode;
      o.hasMode = true;
      o.runRequested = true;
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
      o.workload = *parsedIsa;
      o.hasIsa = true;
      continue;
    }
    if (lowered == L"--duration" || lowered == L"--max-duration") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for " + lowered + L".");
        break;
      }
      auto parsed = ParseUint64(args[++i]);
      if (!parsed || *parsed == 0) {
        AddError(result.errors, lowered + L" requires a positive integer number of seconds.");
        continue;
      }
      o.durationSeconds = *parsed;
      o.hasDuration = true;
      o.runRequested = true;
      continue;
    }
    if (lowered == L"--threads") {
      int v = 0;
      if (TakePositiveInt(args, i, L"--threads", 1, 4096, v, result.errors)) {
        o.run.threadLimit = v;
        o.hasRunTuning = true;
      }
      continue;
    }
    if (lowered == L"--dwell") {
      int v = 0;
      if (TakePositiveInt(args, i, L"--dwell", 1, 86400, v, result.errors)) {
        o.run.coreCycleDwellSec = v;
        o.hasDwell = true;
        o.hasRunTuning = true;
      }
      continue;
    }
    if (lowered == L"--ram-mb") {
      int v = 0;
      if (TakePositiveInt(args, i, L"--ram-mb", 16, 16 * 1024 * 1024, v, result.errors)) {
        o.run.ramBytes = (uint64_t)v << 20;
        o.hasRunTuning = true;
      }
      continue;
    }
    if (lowered == L"--io-mb") {
      int v = 0;
      if (TakePositiveInt(args, i, L"--io-mb", 16, 1024 * 1024, v, result.errors)) {
        o.run.ioBytes = (uint64_t)v << 20;
        o.hasRunTuning = true;
      }
      continue;
    }
    if (lowered == L"--benchmark") {
      o.benchmarkRequested = true;
      o.mode = MODE_BENCHMARK;
      o.hasMode = true;
      o.runRequested = true;
      continue;
    }
    if (lowered == L"--verify") {
      if (i + 1 >= args.size()) {
        AddError(result.errors, L"Missing value for --verify.");
        break;
      }
      o.verifyRequested = true;
      o.verifyHash = args[++i];
      continue;
    }
    if (lowered == L"--repro") {
      if (i + 2 >= args.size()) {
        AddError(result.errors, L"--repro requires both <seed> and <complexity>.");
        break;
      }
      auto seed = ParseUint64(args[++i]);
      auto complexity = ParsePositiveInt(args[++i]);
      if (!seed || !complexity || *complexity > MAX_JOB_COMPLEXITY) {
        AddError(result.errors, L"--repro requires an unsigned 64-bit seed and a complexity "
                                L"between 1 and " + std::to_wstring(MAX_JOB_COMPLEXITY) + L".");
        continue;
      }
      o.reproRequested = true;
      o.reproSeed = *seed;
      o.reproComplexity = *complexity;
      continue;
    }

    AddError(result.errors, L"Unknown option: " + args[i]);
  }

  if (sawLegacyCliFlag && !o.runRequested && !o.verifyRequested && !o.reproRequested)
    o.forceWizard = true;

  if (o.showHelp || o.showVersion)
    return result;

  if (o.verifyRequested && o.reproRequested)
    AddError(result.errors, L"--verify and --repro cannot be combined.");

  if (o.verifyRequested && (o.forceWizard || o.runRequested || o.hasMode || o.hasDuration ||
                            o.hasIsa || o.noAvx512 || o.noAvx2 || o.hasRunTuning)) {
    AddError(result.errors, L"--verify cannot be combined with run, wizard, or ISA options.");
  }

  if (o.reproRequested && (o.forceWizard || o.benchmarkRequested || o.hasDuration ||
                           (o.hasMode && o.mode == MODE_BENCHMARK))) {
    AddError(result.errors,
             L"--repro cannot be combined with --wizard, --benchmark, or duration options.");
  }
  if (o.reproRequested && o.hasRunTuning)
    AddError(result.errors, L"--repro cannot be combined with --threads, --dwell, --no-ram, "
                            L"--no-io, --no-decompress, --ram-mb or --io-mb.");

  if (o.benchmarkRequested && o.hasMode && o.mode != MODE_BENCHMARK)
    AddError(result.errors, L"--benchmark cannot be combined with another --mode.");

  if (o.hasMode && o.mode == MODE_BENCHMARK && o.hasDuration &&
      o.durationSeconds != BENCHMARK_DURATION_SEC) {
    AddError(result.errors,
             L"Benchmark mode always runs for 180 seconds. Remove --duration or set it to 180.");
  }
  if (o.hasDwell && !(o.hasMode && o.mode == MODE_CORE_CYCLE) && !o.forceWizard)
    AddError(result.errors, L"--dwell only applies to --mode corecycle.");

  const bool hasPrimaryAction = o.forceWizard || o.verifyRequested || o.reproRequested ||
                                o.runRequested || o.selfTestRequested ||
                                o.hashRoundtripRequested;
  const bool hasOnlyModifiers =
      !hasPrimaryAction && (o.hasIsa || o.noAvx512 || o.noAvx2 || o.skipTerminalSpawn ||
                            o.quiet || o.hasRunTuning || sawLegacyCliFlag);
  if (hasOnlyModifiers) {
    AddError(result.errors, L"Modifiers require an explicit action. Use --wizard, --mode, "
                            L"--duration, --benchmark, --verify, or --repro.");
  }
  return result;
}

void ApplyCliDefaults(CliOptions &options) {
  if (options.showHelp || options.showVersion || options.verifyRequested ||
      options.reproRequested)
    return;
  if (!options.hasMode)
    options.mode = MODE_DYNAMIC;
  if (options.mode == MODE_BENCHMARK && !options.hasIsa) {
    options.workload = WL_SCALAR_SIM;
    options.hasIsa = true;
  } else if (!options.hasIsa) {
    options.workload = WL_AUTO;
  }
}

namespace {
std::optional<std::string> ReadInteractiveLine() {
  std::string line;
  if (!std::getline(std::cin, line))
    return std::nullopt;
  return line;
}

std::optional<int> AskWizardChoice(const char *prompt, int def, int min, int max) {
  while (true) {
    std::cout << prompt << " [" << def << "]: ";
    auto line = ReadInteractiveLine();
    if (!line) return std::nullopt;
    if (line->empty()) return def;
    int value = 0;
    auto [ptr, ec] = std::from_chars(line->data(), line->data() + line->size(), value, 10);
    if (ec == std::errc() && ptr == line->data() + line->size() && value >= min && value <= max)
      return value;
    std::cout << "Please enter a number between " << min << " and " << max << "." << std::endl;
  }
}

std::optional<std::wstring> AskWizardText(const char *prompt) {
  while (true) {
    std::cout << prompt;
    auto line = ReadInteractiveLine();
    if (!line) return std::nullopt;
    if (!line->empty()) return ToWide(*line);
    std::cout << "Input cannot be empty." << std::endl;
  }
}
} // namespace

bool RunCliWizard(CliOptions &options) {
  // Menu order: 1 Dynamic, 2 Steady, 3 Benchmark, 4 Core cycle, 5 Verify.
  static const int kModeForChoice[] = {0, MODE_DYNAMIC, MODE_STEADY, MODE_BENCHMARK,
                                       MODE_CORE_CYCLE};
  int defaultModeChoice = 1;
  for (int c = 1; c <= 4; ++c)
    if (kModeForChoice[c] == options.mode) defaultModeChoice = c;

  std::cout << "\nSelect Mode:\n"
            << "1. Dynamic (rotating load patterns)\n"
            << "2. Steady (constant full load + RAM/IO)\n"
            << "3. Benchmark (180 s)\n"
            << "4. Core Cycle (one core at a time)\n"
            << "5. Verify Hash\n";
  auto modeChoice = AskWizardChoice("Mode", defaultModeChoice, 1, 5);
  if (!modeChoice) return false;

  if (*modeChoice == 5) {
    auto hash = AskWizardText("Enter hash (SS3-XXXXXXXXXXXXXXXX): ");
    if (!hash) return false;
    options.verifyRequested = true;
    options.verifyHash = *hash;
    options.runRequested = false;
    return true;
  }

  options.hasMode = true;
  options.mode = kModeForChoice[*modeChoice];
  options.runRequested = true;

  std::cout << "\nSelect ISA:\n"
            << "1. Auto\n"
            << "2. AVX-512\n"
            << "3. AVX2\n"
            << "4. SSE2/NEON (synthetic)\n"
            << "5. Scalar (realistic)\n";
  static const WorkloadType kIsaForChoice[] = {WL_AUTO, WL_AUTO, WL_AVX512, WL_AVX2,
                                               WL_SCALAR, WL_SCALAR_SIM};
  int defaultIsaChoice = 1;
  for (int c = 1; c <= 5; ++c)
    if (kIsaForChoice[c] == options.workload) defaultIsaChoice = c;
  if (options.mode == MODE_BENCHMARK && !options.hasIsa) {
    defaultIsaChoice = 5;
    std::cout << "Benchmark default is Scalar (realistic) for comparable hashes.\n";
  }
  auto isaChoice = AskWizardChoice("ISA", defaultIsaChoice, 1, 5);
  if (!isaChoice) return false;
  options.workload = kIsaForChoice[*isaChoice];
  options.hasIsa = true;
  return true;
}
