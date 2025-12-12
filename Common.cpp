// Common.cpp - Global variable definitions and utility function implementations
#include "Common.h"

const std::wstring APP_VERSION = L"3.2";

// --- Global Variables ---
CpuFeatures g_Cpu;
bool g_ForceNoAVX512 = false;
bool g_ForceNoAVX2 = false;

ReproSettings g_Repro;
StressConfig g_ActiveConfig;
std::mutex g_ConfigMtx;
std::atomic<uint64_t> g_ConfigVersion{0};
std::vector<uint64_t> g_ColdStorage;
std::mutex g_StateMtx;

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

std::wstring GetResolvedISAName(int workloadSel) {
#if defined(_M_ARM64) || defined(__aarch64__)
  bool can512 = false;
  bool canAVX2 = false;
#else
  bool can512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
  bool canAVX2 = g_Cpu.hasAVX2 && g_Cpu.hasFMA && !g_ForceNoAVX2;
#endif

  if (workloadSel == WL_AVX512)
    return L"AVX-512 (Forced)";
  if (workloadSel == WL_AVX2)
    return L"AVX2 (Forced)";
  if (workloadSel == WL_SCALAR_MATH)
    return L"Scalar Synthetic (Forced)";
  if (workloadSel == WL_SCALAR_SIM)
    return L"Scalar Realistic (Forced)";

  if (can512)
    return L"AVX-512 (Auto)";
  if (canAVX2)
    return L"AVX2 (Auto)";
  return L"Scalar Realistic (Auto)";
}

// --- AppState Methods ---
void AppState::Log(const std::wstring &msg) {
  std::lock_guard<std::mutex> lk(logMtx);
  if (log.is_open()) {
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
    log << L"[" << tm_buf.tm_hour << L":" << tm_buf.tm_min << L":"
        << tm_buf.tm_sec << L"." << ms.count() << L"] " << msg << std::endl;
  }
  if (g_Repro.active)
    std::wcout << msg << std::endl;
}

void AppState::LogRaw(const std::wstring &msg) {
  std::lock_guard<std::mutex> lk(logMtx);
  if (log.is_open()) {
    log << msg << std::endl;
  }
}

void DetectBestConfig() {
  StressConfig heavyCfg;
  heavyCfg = {8, 2, 0, 0, L"Math Heavy (AVX2/512)"};
  std::lock_guard<std::mutex> lk(g_ConfigMtx);
  g_ActiveConfig = heavyCfg;

  // Log the actual selected mode and ISA
  std::wstring modeName = (g_App.mode == 2)   ? L"Dynamic"
                          : (g_App.mode == 1) ? L"Steady"
                                              : L"Benchmark";
  std::wstring isaName = GetResolvedISAName(g_App.selectedWorkload.load());
  g_App.Log(L"Config auto-selected: " + modeName + L" (" + isaName + L")");
}

// --- Benchmark Hash Validation ---
// Encoding scheme: SS3-XXXXXXXXXXX (11 char Base62 hash)
// Layout: [OS:2][ARCH:2][CPUHASH:8][R0:16][R1:16][R2:16][CHECK:8] = 68 bits

static const wchar_t *B62 =
    L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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

// Scale rate to 16 bits (0-65535), max ~65k jobs/s maps to 65535
static uint16_t ScaleRate(uint64_t rate) {
  if (rate > 65535)
    rate = 65535;
  return (uint16_t)rate;
}

static uint64_t UnscaleRate(uint16_t scaled) { return scaled; }

// Simple XOR obfuscation with rotating key
static uint64_t Obfuscate(uint64_t v) {
  const uint64_t key = 0x5A3C9E7B1F4D2A6Cull;
  v ^= key;
  v = (v << 17) | (v >> 47);
  v ^= (key >> 13);
  return v;
}

static uint64_t Deobfuscate(uint64_t v) {
  const uint64_t key = 0x5A3C9E7B1F4D2A6Cull;
  v ^= (key >> 13);
  v = (v >> 17) | (v << 47);
  v ^= key;
  return v;
}

static std::wstring EncodeB62(uint64_t v, int len) {
  std::wstring result(len, L'0');
  for (int i = len - 1; i >= 0; --i) {
    result[i] = B62[v % 62];
    v /= 62;
  }
  return result;
}

static uint64_t DecodeB62(const std::wstring &s) {
  uint64_t v = 0;
  for (wchar_t c : s) {
    int idx = -1;
    for (int i = 0; i < 62; ++i) {
      if (B62[i] == c) {
        idx = i;
        break;
      }
    }
    if (idx < 0)
      return 0;
    v = v * 62 + idx;
  }
  return v;
}

std::wstring GenerateBenchmarkHash(uint64_t r0, uint64_t r1, uint64_t r2) {
  uint8_t os = GetOsType();
  uint8_t arch = GetArchType();
  uint8_t cpuH = ComputeCpuHash();

  uint16_t sr0 = ScaleRate(r0);
  uint16_t sr1 = ScaleRate(r1);
  uint16_t sr2 = ScaleRate(r2);

  // Pack into 64 bits: [os:2][arch:2][cpu:8][r0:16][r1:16][r2:16] = 60 bits
  uint64_t packed = 0;
  packed |= ((uint64_t)(os & 0x3)) << 58;
  packed |= ((uint64_t)(arch & 0x3)) << 56;
  packed |= ((uint64_t)cpuH) << 48;
  packed |= ((uint64_t)sr0) << 32;
  packed |= ((uint64_t)sr1) << 16;
  packed |= ((uint64_t)sr2);

  // Compute checksum
  uint8_t check = (uint8_t)(packed ^ (packed >> 8) ^ (packed >> 16) ^
                            (packed >> 24) ^ (packed >> 32) ^ (packed >> 40));

  // Add checksum to high bits (use remaining 4 bits + extra)
  packed = (packed & 0x0FFFFFFFFFFFFFFFull) | ((uint64_t)(check & 0xF) << 60);

  // Obfuscate
  uint64_t obf = Obfuscate(packed);

  // Encode to Base62 (64 bits = ~11 chars)
  return L"SS3-" + EncodeB62(obf, 11);
}

HashResult ValidateBenchmarkHash(const std::wstring &hash) {
  HashResult result = {false, {0, 0, 0}, 0, 0, 0};

  // Check prefix
  if (hash.length() < 15 || hash.substr(0, 4) != L"SS3-") {
    return result;
  }

  std::wstring encoded = hash.substr(4);
  if (encoded.length() != 11)
    return result;

  // Decode
  uint64_t obf = DecodeB62(encoded);
  uint64_t packed = Deobfuscate(obf);

  // Extract checksum
  uint8_t storedCheck = (packed >> 60) & 0xF;
  uint64_t dataOnly = packed & 0x0FFFFFFFFFFFFFFFull;

  // Recompute checksum
  uint8_t computedCheck =
      (uint8_t)(dataOnly ^ (dataOnly >> 8) ^ (dataOnly >> 16) ^
                (dataOnly >> 24) ^ (dataOnly >> 32) ^ (dataOnly >> 40));

  if ((computedCheck & 0xF) != storedCheck) {
    return result; // Invalid checksum
  }

  // Extract fields
  result.osType = (dataOnly >> 58) & 0x3;
  result.archType = (dataOnly >> 56) & 0x3;
  result.cpuHash = (dataOnly >> 48) & 0xFF;
  result.rates[0] = UnscaleRate((dataOnly >> 32) & 0xFFFF);
  result.rates[1] = UnscaleRate((dataOnly >> 16) & 0xFFFF);
  result.rates[2] = UnscaleRate(dataOnly & 0xFFFF);
  result.valid = true;

  return result;
}
