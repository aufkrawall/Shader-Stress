// Common.h - Shared types
#pragma once

#include <cstdint>

#if defined(__linux__) || defined(__linux) || defined(linux)
#define PLATFORM_LINUX 1
#elif defined(__APPLE__) || defined(__MACH__)
#define PLATFORM_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS 1
#endif

#ifdef PLATFORM_WINDOWS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <cstdio>
#include <dwmapi.h>
#include <processthreadsapi.h>
#include <shellapi.h>
#include <windows.h>
#include <windowsx.h>
// Note: dbghelp.h removed from Common to avoid pollution, include in
// Platform.cpp if needed
#else
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef PLATFORM_MACOS
#include <sys/sysctl.h>
#include <sys/types.h>

#endif
typedef void *HWND;
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((void *)-1)
#endif

// Architecture-specific intrinsics
// Architecture-specific intrinsics
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
#include <cpuid.h>
#include <immintrin.h>
#ifndef _MSC_VER
#ifndef __popcnt64
#define __popcnt64 __builtin_popcountll
#endif
// Use safe static inlines instead of direct macros for 0-check
static inline uint64_t SafeLZCNT(uint64_t x) {
  return (x == 0) ? 64 : __builtin_clzll(x);
}
static inline uint64_t SafeTZCNT(uint64_t x) {
  return (x == 0) ? 64 : __builtin_ctzll(x);
}
#ifdef _lzcnt_u64
#undef _lzcnt_u64
#endif
#define _lzcnt_u64 SafeLZCNT

#ifdef _tzcnt_u64
#undef _tzcnt_u64
#endif
#define _tzcnt_u64 SafeTZCNT
#endif
#elif defined(_M_ARM64) || defined(__aarch64__)
// ARM64 CLZ counts leading zeros. RBIT+CLZ for CTZ.
static inline uint64_t SafeLZCNT(uint64_t x) {
  return (x == 0) ? 64 : __builtin_clzll(x);
}
static inline uint64_t SafeTZCNT(uint64_t x) {
  return (x == 0) ? 64 : __builtin_ctzll(x);
}
#ifdef _lzcnt_u64
#undef _lzcnt_u64
#endif
#define _lzcnt_u64 SafeLZCNT

#ifdef _tzcnt_u64
#undef _tzcnt_u64
#endif
#define _tzcnt_u64 SafeTZCNT

#ifndef __popcnt64
#define __popcnt64 __builtin_popcountll
#endif
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#endif

using namespace std::chrono_literals;

extern const std::wstring APP_VERSION;
// Numeric version for hash encoding
static const uint8_t APP_VERSION_MAJOR = 3;
static const uint8_t APP_VERSION_MINOR = 4;

constexpr uint64_t GOLDEN_RATIO = 0x9E3779B97F4A7C15ull;
constexpr size_t IO_CHUNK_SIZE = 256 * 1024;
constexpr size_t IO_FILE_SIZE = 512 * 1024 * 1024;
constexpr int BENCHMARK_DURATION_SEC = 180;

struct ScopedHandle {
#ifdef PLATFORM_WINDOWS
  HANDLE h;
  ScopedHandle(HANDLE _h) : h(_h) {}
  ~ScopedHandle() {
    if (h && h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
  }
  operator HANDLE() const { return h; }
#else
  int fd;
  ScopedHandle(int _fd) : fd(_fd) {}
  ~ScopedHandle() {
    if (fd >= 0)
      close(fd);
  }
  operator int() const { return fd; }
#endif
};

struct ScopedMem {
  void *ptr;
  size_t sz;
  ScopedMem(size_t size) : sz(size) {
#ifdef PLATFORM_WINDOWS
    if (size > 0)
      ptr = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
    else
      ptr = nullptr;
#else
    if (size > 0)
      ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    else
      ptr = nullptr;
    if (ptr == MAP_FAILED)
      ptr = nullptr;
#endif
  }
  ~ScopedMem() {
#ifdef PLATFORM_WINDOWS
    if (ptr)
      VirtualFree(ptr, 0, MEM_RELEASE);
#else
    if (ptr)
      munmap(ptr, sz);
#endif
  }
  template <typename T> T *As() { return static_cast<T *>(ptr); }
};

inline uint64_t Rotl64(uint64_t v, unsigned r) {
  return (v << r) | (v >> (64u - r));
}

inline uint64_t GetTick() {
#ifdef PLATFORM_WINDOWS
  return GetTickCount64();
#else
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

std::wstring FmtNum(uint64_t v);
std::wstring FmtTime(uint64_t s);
std::wstring GetArchName();

struct CpuFeatures {
  bool hasAVX2 = false;
  bool hasAVX512F = false;
  bool hasFMA = false;
  std::wstring name;
  std::wstring brand;
};

std::wstring GetCpuBrand();
CpuFeatures GetCpuInfo();

extern CpuFeatures g_Cpu;
extern bool g_ForceNoAVX512;
extern bool g_ForceNoAVX2;

struct ReproSettings {
  bool active = false;
  uint64_t seed = 0;
  int complexity = 0;
};
extern ReproSettings g_Repro;

struct StressConfig {
  int fma_intensity = 1;
  int int_intensity = 1;
  int mem_pressure = 0;
  int branch_freq = 0;
  std::wstring name = L"Default";
};

extern StressConfig g_ActiveConfig;
extern std::mutex g_ConfigMtx;
extern std::atomic<uint64_t> g_ConfigVersion;
extern std::vector<uint64_t> g_ColdStorage;
extern std::mutex g_StateMtx;

enum WorkloadType {
  WL_AUTO = 0,
  WL_AVX512 = 1,
  WL_AVX2 = 2,
  WL_SCALAR_MATH = 3,
  WL_SCALAR_SIM = 4
};

std::wstring GetResolvedISAName(int workloadSel);

struct AppState {
  std::atomic<bool> running{false}, quit{false};
  std::atomic<int> mode{2}, activeCompilers{0}, activeDecomp{0}, loops{0};
  std::atomic<bool> ioActive{false}, ramActive{false};
  std::atomic<bool> resetTimer{false};
  std::atomic<int> currentPhase{0};
  std::atomic<int> selectedWorkload{WL_AUTO};

  std::atomic<uint64_t> shaders{0};
  std::atomic<uint64_t> totalNodes{0};
  std::atomic<uint64_t> errors{0}, elapsed{0};
  std::atomic<uint64_t> currentRate{0};

  std::atomic<uint64_t> benchRates[3];
  std::atomic<int> benchWinner{-1};
  std::atomic<bool> benchComplete{false};

  std::atomic<uint64_t> maxDuration{0};
  std::wstring sigStatus;
  std::wstring benchHash; // Generated hash for benchmark validation
  std::vector<std::wstring> logHistory;
  std::mutex historyMtx;

  // Platform-Specific
  void *windowHandle = nullptr;
  std::ofstream log;
  std::mutex logMtx;

  void Log(const std::wstring &msg);
  void LogRaw(const std::wstring &msg);
};

extern AppState g_App;
extern HWND g_MainWindow;
extern float g_Scale;

inline int S(int v) { return (int)(v * g_Scale); }

void DisablePowerThrottling();
void PinThreadToCore(int coreIdx);

struct alignas(64) HotNode {
  float fRegs[16];
  uint64_t iRegs[8];
};

struct FakeAstNode {
  uint32_t children[4];
  uint32_t meta;
  uint64_t payload;
};

void RunHyperStress_AVX2(uint64_t seed, int complexity,
                         const StressConfig &config);
void RunHyperStress_AVX512(uint64_t seed, int complexity,
                           const StressConfig &config);
void RunHyperStress_Scalar(uint64_t seed, int complexity,
                           const StressConfig &config);
void RunRealisticCompilerSim_V3(uint64_t seed, int complexity,
                                const StressConfig &config);
void UnsafeRunWorkload(uint64_t seed, int complexity,
                       const StressConfig &config);
void SafeRunWorkload(uint64_t seed, int complexity, const StressConfig &config,
                     int threadIdx);

struct ThreadWrapper {
  std::thread t;
  ~ThreadWrapper() {
    if (t.joinable())
      t.join();
  }
};

struct alignas(64) Worker {
  std::atomic<bool> terminate{false};
  std::atomic<uint64_t> localShaders{0};
  std::atomic<uint64_t> lastTick{0};
  uint8_t pad[64];
};

extern std::vector<std::unique_ptr<Worker>> g_Workers;
extern std::vector<std::unique_ptr<Worker>> g_IOThreads;
extern Worker g_RAM;
extern std::vector<std::unique_ptr<ThreadWrapper>> g_Threads;
extern std::unique_ptr<ThreadWrapper> g_DynThread, g_WdThread;

void WorkerThread(int idx);
void IOThread(int ioIdx);
void RAMThread();
void DynamicLoop();
void Watchdog();
void SetWork(int comps, int decomp, bool io, bool ram);

#ifdef PLATFORM_WINDOWS
void InitGDI();
void CleanupGDI();
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l);
#endif
void DetectBestConfig();
void PrintHelp();

// Benchmark hash validation
struct HashResult {
  bool valid = false;
  uint8_t versionMajor = 0;
  uint8_t versionMinor = 0;
  uint8_t os = 0;   // 0=Windows, 1=Linux, 2=macOS, 3=Other
  uint8_t arch = 0; // 0=x86/x64, 1=ARM64
  uint8_t cpuHash = 0;
  uint64_t r0 = 0, r1 = 0, r2 = 0;
};
std::wstring GetOsName(uint8_t os);
std::wstring GetArchNameFromCode(uint8_t arch);
std::wstring GenerateBenchmarkHash(uint64_t r0, uint64_t r1, uint64_t r2);
HashResult ValidateBenchmarkHash(const std::wstring &hash);
