// Common.h - Shared types
#pragma once

// Define _WIN32_WINNT before ANY system includes to prevent _mingw.h from
// setting it to 0x601 (Win7) prematurely. 0x0A00 = Windows 10.
#if defined(_WIN32) || defined(_WIN64)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#endif

#include <cstdint>

#if defined(__linux__) || defined(__linux) || defined(linux)
#define PLATFORM_LINUX 1
#elif defined(__APPLE__) || defined(__MACH__)
#define PLATFORM_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS 1
#endif

#ifdef PLATFORM_WINDOWS
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
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
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
#define NOINLINE __declspec(noinline)
#else
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))
#endif

extern const std::wstring APP_VERSION;

#ifndef APP_VERSION_MAJOR_NUM
#define APP_VERSION_MAJOR_NUM 3
#endif

#ifndef APP_VERSION_MINOR_NUM
#define APP_VERSION_MINOR_NUM 6
#endif

#ifndef APP_VERSION_PATCH_NUM
#define APP_VERSION_PATCH_NUM 0
#endif

// Numeric version for hash encoding
constexpr uint8_t APP_VERSION_MAJOR = static_cast<uint8_t>(APP_VERSION_MAJOR_NUM);
constexpr uint8_t APP_VERSION_MINOR = static_cast<uint8_t>(APP_VERSION_MINOR_NUM);
constexpr uint8_t APP_VERSION_PATCH = static_cast<uint8_t>(APP_VERSION_PATCH_NUM);

constexpr uint64_t GOLDEN_RATIO = 0x9E3779B97F4A7C15ull;
constexpr size_t IO_CHUNK_SIZE = 256 * 1024;
constexpr size_t IO_BLOCK_SIZE = 4096;
constexpr uint64_t IO_FILE_SIZE_DEFAULT = 512ull * 1024 * 1024;
constexpr int BENCHMARK_DURATION_SEC = 180;
// Complexity used for the periodic golden-value verification check.
constexpr int VERIFY_COMPLEXITY = 1000;
// Upper bound for any job complexity (keeps iteration math far from overflow).
constexpr int MAX_JOB_COMPLEXITY = 50000000;
// Default per-core dwell time for core-cycle mode.
constexpr int CORE_CYCLE_DEFAULT_DWELL_SEC = 60;

// Run modes (g_App.mode)
enum RunMode : int {
  MODE_BENCHMARK = 0,
  MODE_STEADY = 1,
  MODE_DYNAMIC = 2,
  MODE_CORE_CYCLE = 3,
};

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
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
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
    // Lock pages to prevent swapping (best-effort; may fail without CAP_IPC_LOCK).
    if (valid) {
      mlock(ptr, size);
    }
#endif
  }

  ~ScopedMem() { Release(); }

  void Release() {
    if (ptr) {
#ifdef PLATFORM_WINDOWS
      VirtualFree(ptr, 0, MEM_RELEASE);
#else
      munmap(ptr, sz);
#endif
    }
    ptr = nullptr;
    valid = false;
  }

  // Disable copy
  ScopedMem(const ScopedMem&) = delete;
  ScopedMem& operator=(const ScopedMem&) = delete;

  // Enable move
  ScopedMem(ScopedMem&& other) noexcept : ptr(other.ptr), sz(other.sz), valid(other.valid) {
    other.ptr = nullptr;
    other.valid = false;
  }
  ScopedMem& operator=(ScopedMem&& other) noexcept {
    if (this != &other) {
      Release();
      ptr = other.ptr;
      sz = other.sz;
      valid = other.valid;
      other.ptr = nullptr;
      other.valid = false;
    }
    return *this;
  }

  explicit operator bool() const { return valid; }
  bool operator!() const { return !valid; }

  template <typename T> T *As() {
    return valid ? static_cast<T *>(ptr) : nullptr;
  }
};

// High 64 bits of a 64x64-bit product (MSVC has no unsigned __int128).
inline uint64_t MulHi64(uint64_t a, uint64_t b) {
#if defined(_MSC_VER) && !defined(__clang__)
  return __umulh(a, b);
#else
  return (uint64_t)(((unsigned __int128)a * b) >> 64);
#endif
}

// Rotate left; the count is taken modulo 64 (callers pass counts >= 64, e.g.
// the realistic sim's bit-vector init). Shifting a 64-bit value by >= 64 is UB.
inline uint64_t Rotl64(uint64_t v, unsigned r) {
  r &= 63u;
  return (v << r) | (v >> ((64u - r) & 63u));
}

// SplitMix64 finalizer: high-quality 64-bit bijective mixer.
inline uint64_t Mix64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xBF58476D1CE4E5B9ull;
  x ^= x >> 27;
  x *= 0x94D049BB133111EBull;
  x ^= x >> 31;
  return x;
}

inline uint64_t GetTick() {
#ifdef PLATFORM_WINDOWS
  return GetTickCount64();
#else
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now)
      .count();
#endif
}

std::wstring FmtNum(uint64_t v);
std::wstring FmtTime(uint64_t s);
std::wstring FmtBytes(uint64_t bytes);
std::wstring FmtHex64(uint64_t v);
// Lossless UTF-8 <-> wide conversion; malformed input becomes U+FFFD.
std::string ToNarrow(const std::wstring &value);
std::wstring ToWide(const std::string &value);
// printf-style formatting into a wide string (ASCII format/arguments only).
std::wstring Fmt(const char *fmt, ...)
#if defined(__clang__) || defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::wstring GetArchName();
std::wstring GetModeName(int mode);

struct CpuFeatures {
  bool hasAVX2 = false;
  bool hasAVX512F = false;
  bool hasFMA = false;
  bool isHybrid = false;    // Intel hybrid (P-core + E-core) topology
  int family = 0;           // CPU family (for tuning)
  int model = 0;            // CPU model (for tuning)
  std::wstring name;
  std::wstring brand;
};

std::wstring GetCpuBrand();
CpuFeatures GetCpuInfo();

extern CpuFeatures g_Cpu;
extern bool g_ForceNoAVX512;
extern bool g_ForceNoAVX2;

// Options that shape a stress run (CLI flags; GUI uses defaults).
struct RunOptions {
  int threadLimit = 0;          // 0 = all logical CPUs allowed by the affinity mask
  bool noRam = false;           // never activate the RAM tester
  bool noIo = false;            // never activate the I/O tester
  bool noDecomp = false;        // turn decompression workers into compute workers
  uint64_t ramBytes = 0;        // 0 = automatic (70% of available RAM, max 16 GiB)
  uint64_t ioBytes = IO_FILE_SIZE_DEFAULT;
  int coreCycleDwellSec = CORE_CYCLE_DEFAULT_DWELL_SEC;
};
extern RunOptions g_RunOpts;

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
  WL_SCALAR = 1,        // Synthetic 128-bit SIMD (SSE2 / NEON) power kernel
  WL_AVX2 = 2,          // Synthetic AVX2/FMA power kernel
  WL_AVX512 = 3,        // Synthetic AVX-512 power kernel
  WL_SCALAR_SIM = 4,    // Realistic compiler simulation (original)
};

std::wstring GetResolvedISAName(int workloadSel);
WorkloadType NormalizeWorkloadSelection(WorkloadType requested);
WorkloadType ResolveSelectedWorkload(int workloadSel);

// Apply configuration based on selected workload (for MAX POWER modes)
void ApplyWorkloadConfig(int workloadSel);

// Packed work assignment so readers always observe a consistent snapshot.
// Layout: [offset:16][comps:16][decomp:16][flags:16] (flags: bit0 io, bit1 ram)
struct WorkAssignment {
  int offset = 0;
  int comps = 0;
  int decomp = 0;
  bool io = false;
  bool ram = false;

  uint64_t Pack() const {
    return ((uint64_t)(uint16_t)offset << 48) | ((uint64_t)(uint16_t)comps << 32) |
           ((uint64_t)(uint16_t)decomp << 16) | (io ? 1u : 0u) | (ram ? 2u : 0u);
  }
  static WorkAssignment Unpack(uint64_t v) {
    WorkAssignment a;
    a.offset = (int)(uint16_t)(v >> 48);
    a.comps = (int)(uint16_t)(v >> 32);
    a.decomp = (int)(uint16_t)(v >> 16);
    a.io = (v & 1u) != 0;
    a.ram = (v & 2u) != 0;
    return a;
  }
  bool operator==(const WorkAssignment &o) const {
    return Pack() == o.Pack();
  }
  bool operator!=(const WorkAssignment &o) const { return !(*this == o); }
};

enum class WorkerRole : int { Idle = 0, Compute = 1, Decompress = 2 };
WorkerRole RoleOf(int workerIdx, const WorkAssignment &a);

struct AppState {
  // Cache-line 1: Worker-Read-Hot — read by ALL worker threads every
  // iteration.  Isolated on its own cache line to avoid MESI invalidation
  // from Watchdog/DynamicLoop writing to other groups.
  alignas(64) std::atomic<bool> running{false};
  std::atomic<bool> quit{false};
  std::atomic<int> mode{MODE_DYNAMIC};
  std::atomic<int> selectedWorkload{WL_AUTO};
  std::atomic<uint32_t> workGen{0};           // bumped on every assignment change
  std::atomic<uint64_t> assignment{0};        // WorkAssignment::Pack()

  // Cache-line 2: Watchdog-Written — also read by workers (shaders, errors)
  // but only rarely.
  alignas(64) std::atomic<uint64_t> shaders{0};
  std::atomic<uint64_t> errors{0};
  std::atomic<uint64_t> elapsed{0};
  std::atomic<uint64_t> currentRate{0};

  // Cache-line 3: DynamicLoop/Bench — written infrequently.
  alignas(64) std::atomic<int> loops{0};
  std::atomic<int> activeCompilers{0};        // display copy of the assignment
  std::atomic<int> activeDecomp{0};
  std::atomic<bool> ioActive{false};
  std::atomic<bool> ramActive{false};
  std::atomic<bool> resetTimer{false};
  std::atomic<int> currentPhase{0};
  std::atomic<uint64_t> benchRates[3];
  std::atomic<int> benchWinner{-1};
  std::atomic<bool> benchComplete{false};
  std::atomic<bool> autoStopBenchmark{
      true}; // Stop and idle after 3min benchmark
  std::atomic<uint64_t> maxDuration{0};
  std::atomic<int> cycleCore{-1};             // core-cycle: current physical core
  std::atomic<uint64_t> cycleNextTick{0};     // core-cycle: tick of next rotation

  // Cache-line 4: Cold data — logging, hash, platform handles.
  alignas(64) std::wstring benchHash;
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
// Sets MXCSR FTZ+DAZ bits on x86-64 for consistent FP behaviour (no-op on ARM64).
// Call once per thread, and in the main thread before InitGoldenValues().
void SetFpuFlushMode();
// Installs process-wide crash handlers (unhandled exceptions / fatal signals)
// that log the faulting thread's job context and write a crash report.
void InstallCrashHandlers();
// Path of the I/O stress temp file (for crash-time cleanup); empty if none.
void SetCrashCleanupFile(const std::wstring &path);

// Windows Power Request API — process-scoped high-performance request.
// Prevents frequency reduction, core parking, deep C-states and throttling.
// Does NOT change the system-wide power scheme.
#ifdef PLATFORM_WINDOWS
void RequestHighPerformance();
void ReleaseHighPerformance();
#endif

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
// Runs the compute workload of the given (resolved) type. Never inlined so all
// callers share one compiled body (bit-identical results for verification).
uint64_t RunComputeWorkload(WorkloadType type, uint64_t seed, int complexity);
void RunPerfStats();
double SampleCpuPackagePower();
struct CpuPowerSample {
  double watts = -1.0;
  uint64_t tick = 0; // monotonic acquisition time, same clock as GetTick()
};
CpuPowerSample SampleCpuPower();
void StartPowerMeasurement();
void ShutdownPowerMeasurement();

struct GoldenValues {
  uint64_t values[5] = {}; // indexed by WorkloadType (0=auto unused, 1-4)
  std::atomic<bool> initialized{false};
};
extern GoldenValues g_Golden;
// Returns the canonical StressConfig used for golden value computation and verification.
StressConfig GetVerifyConfig();
void InitGoldenValues();

struct ThreadWrapper {
  std::thread t;

  ~ThreadWrapper() {
    if (t.joinable()) {
      t.join();
    }
  }
};

enum class WorkerState {
  Idle = 0,
  Running = 1,
  Stopped = 2
};

struct alignas(64) Worker {
  std::atomic<bool> terminate{false};
  std::atomic<uint64_t> localShaders{0};
  std::atomic<uint64_t> lastTick{0};
  std::atomic<WorkerState> state{WorkerState::Idle};
  std::atomic<int> lp{-1};   // logical CPU this worker is pinned to (-1 = unpinned)
  // alignas(64) pads the struct to exactly 64 bytes (one cache line).
};
static_assert(sizeof(Worker) == 64, "Worker must be exactly one cache line");

extern std::vector<std::unique_ptr<Worker>> g_Workers;
extern std::vector<std::unique_ptr<ThreadWrapper>> g_Threads;
extern std::unique_ptr<ThreadWrapper> g_DynThread, g_WdThread;

void WorkerThread(int idx);
void DynamicLoop();
void CoreCycleLoop();
void Watchdog();
// Assigns work. offset = first worker index of the active window.
void SetWork(int comps, int decomp, bool io, bool ram, int offset = 0);
// Stops IO/RAM testers and releases their memory/temp files.
void ReleaseAuxResources();
// Starts the worker pool / control threads for the current g_App.mode.
void StartModeWork();
// Creates g_Workers according to the topology and g_RunOpts.threadLimit.
int CreateWorkerPool();

#ifdef PLATFORM_WINDOWS
void InitGDI();
void CleanupGDI();
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l);
#endif
void DetectBestConfig();

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
