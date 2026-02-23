// Common.cpp - Global variable definitions and utility function implementations
#include "Common.h"

const std::wstring APP_VERSION = L"3.5.2";

// --- Global Variables ---
CpuFeatures g_Cpu;
bool g_ForceNoAVX512 = false;
bool g_ForceNoAVX2 = false;

ReproSettings g_Repro;
StressConfig g_ActiveConfig;
std::mutex g_ConfigMtx;
std::atomic<uint64_t> g_ConfigVersion{0};
std::mutex g_StateMtx;

GoldenValues g_Golden;

AppState g_App;
HWND g_MainWindow = nullptr;
float g_Scale = 1.0f;

std::vector<std::unique_ptr<Worker>> g_Workers;
std::vector<std::unique_ptr<Worker>> g_IOThreads;
Worker g_RAM;
std::vector<std::unique_ptr<ThreadWrapper>> g_Threads;
std::unique_ptr<ThreadWrapper> g_DynThread, g_WdThread;

// --- Utility Functions ---
std::wstring FmtNum(uint64_t v) {
  if (v < 1000)
    return std::to_wstring(v);
  wchar_t buf[64];
  double n = (double)v;
  const wchar_t *suffix = L"";
  if (v >= 1000000) {
    n /= 1000000.0;
    suffix = L"M";
  } else {
    n /= 1000.0;
    suffix = L"k";
  }
#ifdef _WIN32
  _snwprintf_s(buf, _TRUNCATE, L"%.1f%s", n, suffix);
#else
  swprintf(buf, 64, L"%.1f%s", n, suffix);
#endif
  std::wstring res(buf);
  std::replace(res.begin(), res.end(), L',', L'.');
  return res;
}

std::wstring FmtTime(uint64_t s) {
  std::wstringstream ss;
  ss << std::setfill(L'0') << std::setw(2) << (s / 3600) << L":" << std::setw(2)
     << ((s % 3600) / 60) << L":" << std::setw(2) << (s % 60);
  return ss.str();
}

std::wstring GetArchName() {
#if defined(_M_ARM64) || defined(__aarch64__)
  return L"ARM64";
#elif defined(_M_AMD64) || defined(__x86_64__)
  return L"x64";
#elif defined(_M_IX86) || defined(__i386__)
  return L"x86";
#else
  return L"Unknown";
#endif
}

static bool HasUsableAVX2() {
  return g_Cpu.hasAVX2 && g_Cpu.hasFMA && !g_ForceNoAVX2;
}

static bool HasUsableAVX512() { return g_Cpu.hasAVX512F && !g_ForceNoAVX512; }

WorkloadType NormalizeWorkloadSelection(WorkloadType requested) {
  switch (requested) {
  case WL_AUTO:
  case WL_SCALAR:
  case WL_SCALAR_SIM:
    return requested;
  case WL_AVX512:
    if (HasUsableAVX512())
      return WL_AVX512;
    if (HasUsableAVX2())
      return WL_AVX2;
    return WL_SCALAR;
  case WL_AVX2:
    return HasUsableAVX2() ? WL_AVX2 : WL_SCALAR;
  default:
    return WL_SCALAR;
  }
}

WorkloadType ResolveSelectedWorkload(int workloadSel) {
  WorkloadType requested =
      NormalizeWorkloadSelection((WorkloadType)workloadSel);
  if (requested == WL_AUTO) {
    if (HasUsableAVX512())
      return WL_AVX512;
    if (HasUsableAVX2())
      return WL_AVX2;
    return WL_SCALAR;
  }
  return requested;
}

std::wstring GetResolvedISAName(int workloadSel) {
  WorkloadType type = ResolveSelectedWorkload(workloadSel);

  switch (type) {
  case WL_SCALAR:
    return L"Scalar (Synthetic)";
  case WL_AVX2:
    return L"AVX2";
  case WL_AVX512:
    return L"AVX-512";
  case WL_SCALAR_SIM:
    return L"Realistic Compiler Sim";
  default:
    return L"Unknown";
  }
}

// Helper for logging
static std::string ToLogStr(const std::wstring &w) {
  if (w.empty())
    return "";
#ifdef PLATFORM_WINDOWS
  int size = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr,
                                 0, nullptr, nullptr);
  std::string s(size, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], size, nullptr,
                      nullptr);
  return s;
#else
  // Use std::wcstombs with locale for proper UTF-8 conversion
  // Fallback to lossy ASCII-only if locale doesn't support it
  // Note: setlocale is called once at startup; not repeated here (thread safety)
  const wchar_t* wstr = w.c_str();
  size_t len = std::wcstombs(nullptr, wstr, 0);
  if (len != static_cast<size_t>(-1) && len > 0) {
    std::string s(len, 0);
    std::wcstombs(&s[0], wstr, len);
    return s;
  }
  // Fallback: lossy ASCII-only conversion
  std::string s;
  s.reserve(w.size());
  for (wchar_t c : w) {
    if (c < 128)
      s.push_back(static_cast<char>(c));
    else
      s.push_back('?');
  }
  return s;
#endif
}

// --- AppState Methods ---
// Logs with timestamp to both valid outputs and history
void AppState::Log(const std::wstring &msg) {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::tm tm_buf;
#ifdef PLATFORM_WINDOWS
  localtime_s(&tm_buf, &time);
#else
  localtime_r(&time, &tm_buf);
#endif

  std::wstringstream ss;
  ss << L"[" << std::setfill(L'0') << std::setw(2) << tm_buf.tm_hour << L":"
     << std::setw(2) << tm_buf.tm_min << L":" << std::setw(2) << tm_buf.tm_sec
     << L"." << std::setw(3) << ms.count() << L"] " << msg;

  std::wstring fullMsg = ss.str();

  // Send to history (for clipboard) - uses deque for O(1) push/pop
  {
    std::lock_guard<std::mutex> lk(historyMtx);
    logHistory.push_back(fullMsg);
    while (logHistory.size() > MAX_LOG_HISTORY)
      logHistory.pop_front();
  }

  // Send to file/console
  std::lock_guard<std::mutex> lk(logMtx);
  if (log.is_open()) {
    log << ToLogStr(fullMsg) << std::endl;
  }
  if (g_Repro.active)
    std::wcout << msg << std::endl;
}

void AppState::LogRaw(const std::wstring &msg) {
  {
    std::lock_guard<std::mutex> lk(historyMtx);
    logHistory.push_back(msg);
    while (logHistory.size() > MAX_LOG_HISTORY)
      logHistory.pop_front();
  }
  std::lock_guard<std::mutex> lk(logMtx);
  if (log.is_open()) {
    log << ToLogStr(msg) << std::endl;
  }
}

void AppState::SetBenchHash(const std::wstring &hash) {
  std::lock_guard<std::mutex> lk(historyMtx);
  benchHash = hash;
}

std::wstring AppState::GetBenchHash() const {
  std::lock_guard<std::mutex> lk(historyMtx);
  return benchHash;
}

std::vector<std::wstring> AppState::GetLogHistorySnapshot() const {
  std::lock_guard<std::mutex> lk(historyMtx);
  return std::vector<std::wstring>(logHistory.begin(), logHistory.end());
}

void DetectBestConfig() {
  StressConfig heavyCfg;
  heavyCfg.fma_intensity = 8;
  heavyCfg.int_intensity = 2;
  heavyCfg.div_intensity = 1;
  heavyCfg.bit_intensity = 0;
  heavyCfg.branch_intensity = 0;
  heavyCfg.int_simd_intensity = 0;
  heavyCfg.mem_pressure = 0;
  heavyCfg.shuffle_freq = 8;
  heavyCfg.cache_stride = 32768;
  heavyCfg.name = L"Math Heavy (AVX2/512)";
  std::lock_guard<std::mutex> lk(g_ConfigMtx);
  g_ActiveConfig = heavyCfg;

  // Log the actual selected mode and ISA
  std::wstring modeName = (g_App.mode == 2)   ? L"Dynamic"
                          : (g_App.mode == 1) ? L"Steady"
                                              : L"Benchmark";
  std::wstring isaName = GetResolvedISAName(g_App.selectedWorkload.load());
  g_App.Log(L"Config auto-selected: " + modeName + L" (" + isaName + L")");
}

// --- Golden Value Initialization ---
void InitGoldenValues() {
  StressConfig defaultCfg;
  defaultCfg.fma_intensity = 8;
  defaultCfg.int_intensity = 2;
  defaultCfg.div_intensity = 1;
  defaultCfg.bit_intensity = 0;
  defaultCfg.branch_intensity = 0;
  defaultCfg.int_simd_intensity = 0;
  defaultCfg.mem_pressure = 0;
  defaultCfg.shuffle_freq = 8;
  defaultCfg.cache_stride = 32768;

  // Compute golden values for each workload type
  g_Golden.values[WL_SCALAR] = RunHyperStress_Scalar(42, VERIFY_COMPLEXITY, defaultCfg);
  g_Golden.values[WL_SCALAR_SIM] =
      RunRealisticCompilerSim_V3(42, VERIFY_COMPLEXITY, defaultCfg);

  if (g_Cpu.hasAVX2 && g_Cpu.hasFMA && !g_ForceNoAVX2)
    g_Golden.values[WL_AVX2] = RunHyperStress_AVX2(42, VERIFY_COMPLEXITY, defaultCfg);
  if (g_Cpu.hasAVX512F && !g_ForceNoAVX512)
    g_Golden.values[WL_AVX512] = RunHyperStress_AVX512(42, VERIFY_COMPLEXITY, defaultCfg);

  g_Golden.initialized = true;
}

// --- Benchmark Hash Validation ---
// Encoding scheme: SS3-XXXXXXXXXXXXXXXX (16 char Base62 hash)
// Payload (92 bits): [Data:60][Checksum:32]
// Data Layout: [OS:2][ARCH:2][CPUHASH:8][R0:16][R1:16][R2:16]

static const wchar_t *B62 =
    L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// --- 128-bit Helper for Base62 Encoding/Encryption ---
struct u128 {
  uint64_t lo, hi;
};

// Portable FNV-1a 32-bit hash
static uint32_t FNV1a(const void *data, size_t len) {
  uint32_t hash = 2166136261u;
  const uint8_t *p = (const uint8_t *)data;
  for (size_t i = 0; i < len; ++i) {
    hash ^= p[i];
    hash *= 16777619u;
  }
  return hash;
}

static uint64_t DivMod62(u128 &n) {
  uint64_t rem = 0;
  uint32_t chunks[4];
  chunks[3] = (uint32_t)(n.hi >> 32);
  chunks[2] = (uint32_t)(n.hi);
  chunks[1] = (uint32_t)(n.lo >> 32);
  chunks[0] = (uint32_t)(n.lo);

  for (int i = 3; i >= 0; --i) {
    uint64_t cur = chunks[i] + (rem << 32);
    chunks[i] = (uint32_t)(cur / 62);
    rem = cur % 62;
  }

  n.hi = ((uint64_t)chunks[3] << 32) | chunks[2];
  n.lo = ((uint64_t)chunks[1] << 32) | chunks[0];
  return rem;
}

static void MulAdd62(u128 &n, uint64_t add) {
  uint64_t carry = add;
  uint32_t chunks[4];
  chunks[0] = (uint32_t)n.lo;
  chunks[1] = (uint32_t)(n.lo >> 32);
  chunks[2] = (uint32_t)n.hi;
  chunks[3] = (uint32_t)(n.hi >> 32);

  for (int i = 0; i < 4; ++i) {
    uint64_t res = (uint64_t)chunks[i] * 62 + carry;
    chunks[i] = (uint32_t)res;
    carry = res >> 32;
  }
  n.lo = ((uint64_t)chunks[1] << 32) | chunks[0];
  n.hi = ((uint64_t)chunks[3] << 32) | chunks[2];
}

// Reversible XOR mixing for 128-bit block (Preserves bit width of Hi/Lo)
static void Mix(u128 &v) {
  // Ensure we stay within 92 bits (Lo: 64, Hi: 28)
  // Max Hi = 0x0FFFFFFF
  const uint64_t K_LO = 0x9E3779B97F4A7C15ull;
  const uint64_t K_HI = 0x5A3C9E7B1F4D2A6Cull & 0x0FFFFFFFull;

  v.lo ^= K_LO;
  v.hi ^= K_HI;

  // Scramble Lo slightly based on Hi (safe as Lo is 64 bits)
  v.lo ^= (v.hi << 13) | (v.hi >> 15);
}

static void Unmix(u128 &v) {
  const uint64_t K_LO = 0x9E3779B97F4A7C15ull;
  const uint64_t K_HI = 0x5A3C9E7B1F4D2A6Cull & 0x0FFFFFFFull;

  v.lo ^= (v.hi << 13) | (v.hi >> 15);
  v.hi ^= K_HI;
  v.lo ^= K_LO;
}

static uint8_t ComputeCpuHash() {
  uint32_t h = 0x811c9dc5;
  for (wchar_t c : g_Cpu.brand) {
    h ^= (uint8_t)c;
    h *= 0x01000193;
  }
  return (uint8_t)(h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24));
}

static uint8_t GetOsType() {
#ifdef PLATFORM_WINDOWS
  return 0;
#elif defined(PLATFORM_LINUX)
  return 1;
#elif defined(PLATFORM_MACOS)
  return 2;
#else
  return 3;
#endif
}

static uint8_t GetArchType() {
#if defined(_M_ARM64) || defined(__aarch64__)
  return 1;
#else
  return 0;
#endif
}

static uint16_t ScaleRate(uint64_t rate) {
  return (rate > 65535) ? 65535 : (uint16_t)rate;
}

static uint64_t UnscaleRate(uint16_t scaled) { return scaled; }

std::wstring GetOsName(uint8_t os) {
  switch (os) {
  case 0:
    return L"Windows";
  case 1:
    return L"Linux";
  case 2:
    return L"macOS";
  default:
    return L"Unknown";
  }
}

std::wstring GetArchNameFromCode(uint8_t arch) {
  return (arch == 1) ? L"ARM64" : L"x64";
}

std::wstring GenerateBenchmarkHash(uint64_t r0, uint64_t r1, uint64_t r2) {
  uint8_t verMaj = APP_VERSION_MAJOR & 0xF;
  uint8_t verMin = APP_VERSION_MINOR & 0xF;
  uint8_t osType = GetOsType() & 0x3;     // 2 bits
  uint8_t archType = GetArchType() & 0x1; // 1 bit
  uint8_t cpuH = ComputeCpuHash() & 0x1F; // 5 bits (expanded from 4)

  uint16_t sr0 = ScaleRate(r0);
  uint16_t sr1 = ScaleRate(r1);
  uint16_t sr2 = ScaleRate(r2);

  // Hash Layout (64 bits data):
  // [Major:4][Minor:4][OS:2][Arch:1][CPU:5][R0:16][R1:16][R2:16]

  uint64_t data = 0;
  data |= ((uint64_t)verMaj) << 60;
  data |= ((uint64_t)verMin) << 56;
  data |= ((uint64_t)osType) << 54;
  data |= ((uint64_t)archType) << 53;
  data |= ((uint64_t)cpuH) << 48;
  data |= ((uint64_t)sr0) << 32;
  data |= ((uint64_t)sr1) << 16;
  data |= ((uint64_t)sr2);

  uint32_t check = FNV1a(&data, sizeof(data));

  u128 payload;
  payload.lo = (data << 32) | check;
  payload.hi = (data >> 32);

  Mix(payload);

  std::wstring result(16, L'0');
  for (int i = 15; i >= 0; --i) {
    result[i] = B62[DivMod62(payload)];
  }

  return L"SS3-" + result;
}

HashResult ValidateBenchmarkHash(const std::wstring &hash) {
  HashResult result;

  // Check prefix and length
  if (hash.length() != 20 || hash.substr(0, 4) != L"SS3-") {
    return result;
  }

  std::wstring encoded = hash.substr(4);
  u128 payload = {0, 0};

  // Decode Base62
  for (wchar_t c : encoded) {
    int idx = -1;
    for (int i = 0; i < 62; ++i) {
      if (B62[i] == c) {
        idx = i;
        break;
      }
    }
    if (idx < 0)
      return result;
    MulAdd62(payload, idx);
  }

  // De-Obfuscate
  Unmix(payload);

  // Extract Data and Checksum
  // layout: lo = (low_data << 32) | check
  //         hi = high_data
  uint32_t storedCheck = (uint32_t)(payload.lo & 0xFFFFFFFF);
  uint64_t data = (payload.hi << 32) | (payload.lo >> 32);

  // Data is now 64 bits (no mask needed)

  // Recompute Checksum
  uint32_t computedCheck = FNV1a(&data, sizeof(data));

  if (computedCheck != storedCheck) {
    return result; // Invalid checksum (Tampered!)
  }

  result.valid = true;
  // Unpack: [Major:4][Minor:4][OS:2][Arch:1][CPU:5][R0:16][R1:16][R2:16]

  result.versionMajor = (data >> 60) & 0xF;
  result.versionMinor = (data >> 56) & 0xF;
  result.os = (data >> 54) & 0x3;
  result.arch = (data >> 53) & 0x1;
  result.cpuHash = (data >> 48) & 0x1F; // 5-bit CPU hash
  result.r0 = (data >> 32) & 0xFFFF;
  result.r1 = (data >> 16) & 0xFFFF;
  result.r2 = (data) & 0xFFFF;

  return result;
}
