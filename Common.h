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
#include <optional>
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
static const uint8_t APP_VERSION_MINOR = 5;
static const uint8_t APP_VERSION_PATCH = 1;

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
  bool valid;
  
  explicit ScopedMem(size_t size) : sz(size), valid(false) {
    if (size == 0) {
      ptr = nullptr;
      return;
    }
#ifdef PLATFORM_WINDOWS
    ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    valid = (ptr != nullptr);
#else
    ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    valid = (ptr != MAP_FAILED);
    if (!valid) ptr = nullptr;
#endif
  }
  
  ~ScopedMem() {
    if (ptr) {
#ifdef PLATFORM_WINDOWS
      VirtualFree(ptr, 0, MEM_RELEASE);
#else
      munmap(ptr, sz);
#endif
    }
  }
  
  // Disable copy
  ScopedMem(const ScopedMem&) = delete;
  ScopedMem& operator=(const ScopedMem&) = delete;
  
  // Enable move
  ScopedMem(ScopedMem&& other) noexcept : ptr(other.ptr), sz(other.sz), valid(other.valid) {
    other.ptr = nullptr;
    other.valid = false;
  }
  
  explicit operator bool() const { return valid; }
  bool operator!() const { return !valid; }
  
  template <typename T> T *As() { 
    return valid ? static_cast<T *>(ptr) : nullptr; 
  }
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

// Minimum time slice for Ultra stress workloads (milliseconds)
constexpr int MIN_SLICE_MS = 50;

std::wstring FmtNum(uint64_t v);
std::wstring FmtTime(uint64_t s);
std::wstring GetArchName();

struct CpuFeatures {
  bool hasAVX2 = false;
  bool hasAVX512F = false;
  bool hasFMA = false;
  int family = 0;       // CPU family (for tuning)
  int model = 0;        // CPU model (for tuning)
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
  int div_intensity = 0;
  int bit_intensity = 0;
  int branch_intensity = 0;
  int int_simd_intensity = 0;
  int mem_pressure = 0;
  int shuffle_freq = 8;
  size_t cache_stride = 32768;
  std::wstring name = L"Default";
};

extern StressConfig g_ActiveConfig;
extern std::mutex g_ConfigMtx;
extern std::atomic<uint64_t> g_ConfigVersion;
extern std::mutex g_StateMtx;

enum WorkloadType {
  WL_AUTO = 0,          // Auto-select best available
  WL_SCALAR = 1,        // Maximum power scalar (register pressure + ALU)
  WL_AVX2 = 2,          // Maximum power AVX2 with parallel FMA chains
  WL_AVX512 = 3,        // Maximum power AVX-512 with parallel FMA chains
  WL_SCALAR_SIM = 4,    // Realistic compiler simulation (original)
};

std::wstring GetResolvedISAName(int workloadSel);

// Apply configuration based on selected workload (for MAX POWER modes)
void ApplyWorkloadConfig(int workloadSel);

struct AppState {
  // Control flags use seq_cst for proper synchronization between threads
  std::atomic<bool> running{false};
  std::atomic<bool> quit{false};
  std::atomic<int> mode{2};
  std::atomic<int> activeCompilers{0};
  std::atomic<int> activeDecomp{0};
  std::atomic<int> loops{0};
  std::atomic<bool> ioActive{false};
  std::atomic<bool> ramActive{false};
  std::atomic<bool> resetTimer{false};
  std::atomic<int> currentPhase{0};
  std::atomic<int> selectedWorkload{WL_AUTO};

  // Statistics counters
  std::atomic<uint64_t> shaders{0};
  std::atomic<uint64_t> totalNodes{0};
  std::atomic<uint64_t> errors{0};
  std::atomic<uint64_t> elapsed{0};
  std::atomic<uint64_t> currentRate{0};

  std::atomic<uint64_t> benchRates[3];
  std::atomic<int> benchWinner{-1};
  std::atomic<bool> benchComplete{false};
  std::atomic<bool> autoStopBenchmark{
      true}; // Stop and idle after 3min benchmark

  std::atomic<uint64_t> maxDuration{0};
  std::wstring sigStatus;
  std::wstring benchHash; // Generated hash for benchmark validation
  static constexpr size_t MAX_LOG_HISTORY = 1000;
  std::deque<std::wstring> logHistory;
  mutable std::mutex historyMtx;

  // Platform-Specific
  void *windowHandle = nullptr;
  std::ofstream log;
  std::mutex logMtx;

  void Log(const std::wstring &msg);
  void LogRaw(const std::wstring &msg);

  // Thread-safe access to benchHash
  void SetBenchHash(const std::wstring &hash);
  std::wstring GetBenchHash() const;

  // Thread-safe access to log history for reading
  std::vector<std::wstring> GetLogHistorySnapshot() const;
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

uint64_t RunHyperStress_AVX2(uint64_t seed, int complexity,
                             const StressConfig &config);
uint64_t RunHyperStress_AVX512(uint64_t seed, int complexity,
                               const StressConfig &config);
uint64_t RunHyperStress_Scalar(uint64_t seed, int complexity,
                               const StressConfig &config);
uint64_t RunRealisticCompilerSim_V3(uint64_t seed, int complexity,
                                    const StressConfig &config);
uint64_t UnsafeRunWorkload(uint64_t seed, int complexity,
                           const StressConfig &config);
uint64_t SafeRunWorkload(uint64_t seed, int complexity,
                         const StressConfig &config, int threadIdx);

struct GoldenValues {
  uint64_t values[5] = {}; // indexed by WorkloadType (0=auto unused, 1-4)
  bool initialized = false;
};
extern GoldenValues g_Golden;
void InitGoldenValues();

struct ThreadWrapper {
  std::thread t;
  
  ~ThreadWrapper() {
    if (t.joinable()) {
      // Threads should exit quickly when terminate flag is set
      // Just join directly - don't poll with timeout
      t.join();
    }
  }
};

enum class WorkerState {
  Idle = 0,
  Running = 1,
  Terminating = 2,
  Stopped = 3
};

struct alignas(64) Worker {
  std::atomic<bool> terminate{false};
  std::atomic<uint64_t> localShaders{0};
  std::atomic<uint64_t> lastTick{0};
  std::atomic<WorkerState> state{WorkerState::Idle};
  uint8_t pad[64 - sizeof(std::atomic<WorkerState>)];
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

#if !defined(PLATFORM_WINDOWS)
void InstallCrashHandlers();
#endif

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
