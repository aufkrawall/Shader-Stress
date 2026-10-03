// Platform.cpp - Cross-platform helpers: power requests, FPU mode, crash handlers
#include "Common.h"
#include "Workloads.h"
#include <csignal>

#ifdef PLATFORM_LINUX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sched.h>
#endif

#ifdef PLATFORM_WINDOWS
#include <dbghelp.h>
#include <powerbase.h>
#include <timeapi.h>
// Power request handle — creation/teardown at startup/shutdown
static HANDLE g_PowerRequest = INVALID_HANDLE_VALUE;
static bool g_TimerPeriodSet = false;

void RequestHighPerformance() {
  REASON_CONTEXT context = {};
  context.Version = POWER_REQUEST_CONTEXT_VERSION;
  context.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
  context.Reason.SimpleReasonString = const_cast<LPWSTR>(L"ShaderStress - max power stress test");
  g_PowerRequest = PowerCreateRequest(&context);
  if (g_PowerRequest != INVALID_HANDLE_VALUE) {
    PowerSetRequest(g_PowerRequest, PowerRequestExecutionRequired);
  }
  // 1 ms timer resolution while running: sharp load steps in dynamic mode.
  g_TimerPeriodSet = timeBeginPeriod(1) == TIMERR_NOERROR;
}

void ReleaseHighPerformance() {
  if (g_PowerRequest != INVALID_HANDLE_VALUE) {
    PowerClearRequest(g_PowerRequest, PowerRequestExecutionRequired);
    CloseHandle(g_PowerRequest);
    g_PowerRequest = INVALID_HANDLE_VALUE;
  }
  if (g_TimerPeriodSet) {
    timeEndPeriod(1);
    g_TimerPeriodSet = false;
  }
}
#endif

void DisablePowerThrottling() {
#ifdef PLATFORM_WINDOWS
  // Opt this thread out of EcoQoS / execution-speed throttling.
  PROCESS_POWER_THROTTLING_STATE PowerThrottling{};
  PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
  PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
  PowerThrottling.StateMask = 0;
  SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &PowerThrottling,
                       sizeof(PowerThrottling));
#elif defined(PLATFORM_LINUX)
  // Best effort (needs root): performance governor / EPP for this CPU.
  int cpuIdx = sched_getcpu();
  if (cpuIdx >= 0) {
    const char *files[] = {"/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor",
                           "/sys/devices/system/cpu/cpu%d/cpufreq/energy_performance_preference"};
    for (const char *fmt : files) {
      char path[128];
      int len = snprintf(path, sizeof(path), fmt, cpuIdx);
      if (len <= 0 || len >= (int)sizeof(path)) continue;
      int fd = open(path, O_WRONLY);
      if (fd >= 0) {
        ssize_t w = write(fd, "performance", 11);
        (void)w;
        close(fd);
      }
    }
  }
#endif
  // macOS: No equivalent needed (no power throttling API)
}

void SetFpuFlushMode() {
#if defined(__x86_64__) || defined(_M_X64)
  // Enable Flush-To-Zero (FTZ, bit 15) and Denormals-Are-Zero (DAZ, bit 6) in
  // MXCSR so every thread has identical FP semantics (bit-exact results).
  _mm_setcsr(_mm_getcsr() | 0x8040);
#endif
  // ARM64: denormal handling is configured globally and NEON never traps.
}

// ---------------------------------------------------------------------------
// Crash handling. Everything below must stay allocation-free on the crash path.
// ---------------------------------------------------------------------------
namespace {
#ifdef PLATFORM_WINDOWS
wchar_t s_cleanupFileW[MAX_PATH * 2] = {};
#else
char s_cleanupFileA[4096] = {};
#endif
std::atomic<bool> s_crashing{false};

const char *WorkloadCliName(int workload) {
  switch (workload) {
  case WL_SCALAR: return "scalar";
  case WL_AVX2: return "avx2";
  case WL_AVX512: return "avx512";
  case WL_SCALAR_SIM: return "scalar-sim";
  case JOB_WORKLOAD_DECOMPRESS: return "decompress";
  case JOB_WORKLOAD_RAM: return "ram-tester";
  case JOB_WORKLOAD_IO: return "io-tester";
  default: return "none";
  }
}

// Formats the crashing thread's job context into `buf`.
int FormatJobContext(char *buf, size_t cap) {
  const JobContext &ctx = CurrentJob();
  const char *wl = WorkloadCliName(ctx.workload);
  int n = snprintf(buf, cap,
                   "Thread: worker %d, logical CPU %d\nWorkload: %s\nSeed: %llu\nComplexity: %d\n",
                   ctx.worker, ctx.lp, wl, (unsigned long long)ctx.seed, ctx.complexity);
  if (n > 0 && (size_t)n < cap && ctx.workload >= WL_SCALAR && ctx.workload <= WL_SCALAR_SIM) {
    n += snprintf(buf + n, cap - (size_t)n, "Repro: --repro %llu %d --isa %s\n",
                  (unsigned long long)ctx.seed, ctx.complexity, wl);
  }
  return n;
}
} // namespace

void SetCrashCleanupFile(const std::wstring &path) {
#ifdef PLATFORM_WINDOWS
  size_t n = std::min(path.size(), (size_t)(MAX_PATH * 2 - 1));
  for (size_t i = 0; i < n; ++i) s_cleanupFileW[i] = path[i];
  s_cleanupFileW[n] = 0;
#else
  size_t n = std::min(path.size(), sizeof(s_cleanupFileA) - 1);
  for (size_t i = 0; i < n; ++i) s_cleanupFileA[i] = (char)path[i];
  s_cleanupFileA[n] = 0;
#endif
}

#ifdef PLATFORM_WINDOWS
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS *ep) {
  if (s_crashing.exchange(true))
    return EXCEPTION_EXECUTE_HANDLER; // another thread is already reporting
  SYSTEMTIME st;
  GetLocalTime(&st);
  const JobContext &ctx = CurrentJob();
  char dir[96];
  snprintf(dir, sizeof(dir), "Crash_%04u-%02u-%02u_%02u-%02u-%02u_W%d", st.wYear, st.wMonth,
           st.wDay, st.wHour, st.wMinute, st.wSecond, ctx.worker);
  CreateDirectoryA(dir, nullptr);

  char info[2048];
  const EXCEPTION_RECORD *er = ep ? ep->ExceptionRecord : nullptr;
  uintptr_t addr = er ? (uintptr_t)er->ExceptionAddress : 0;
  uintptr_t base = (uintptr_t)GetModuleHandleW(nullptr);
  int n = snprintf(info, sizeof(info),
                   "ShaderStress %d.%d.%d crash\nException: 0x%08lX at 0x%016llX "
                   "(ShaderStress.exe+0x%llX)\n",
                   APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH,
                   er ? (unsigned long)er->ExceptionCode : 0ul, (unsigned long long)addr,
                   (unsigned long long)(addr - base));
  if (n > 0 && (size_t)n < sizeof(info))
    n += FormatJobContext(info + n, sizeof(info) - (size_t)n);
  if (n > 0 && (size_t)n < sizeof(info)) {
    n += snprintf(info + n, sizeof(info) - (size_t)n, "CPU: ");
    for (wchar_t c : g_Cpu.brand) {
      if ((size_t)n + 2 >= sizeof(info)) break;
      info[n++] = (c < 128) ? (char)c : '?';
    }
    if ((size_t)n + 2 < sizeof(info)) {
      info[n++] = '\n';
      info[n] = 0;
    }
  }
  if (n < 0) n = 0;
  if ((size_t)n >= sizeof(info)) n = (int)sizeof(info) - 1;

  char path[160];
  snprintf(path, sizeof(path), "%s\\crash_info.txt", dir);
  HANDLE hInfo = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hInfo != INVALID_HANDLE_VALUE) {
    DWORD w = 0;
    WriteFile(hInfo, info, (DWORD)n, &w, nullptr);
    CloseHandle(hInfo);
  }
  HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
  if (hErr && hErr != INVALID_HANDLE_VALUE) {
    DWORD w = 0;
    WriteFile(hErr, "\n[CRASH]\n", 9, &w, nullptr);
    WriteFile(hErr, info, (DWORD)n, &w, nullptr);
  }

  // Compact dump (stacks, registers, referenced memory) — never full memory,
  // which would include the multi-GiB RAM-test buffers.
  snprintf(path, sizeof(path), "%s\\crash.dmp", dir);
  HANDLE hDump = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hDump != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION mdei;
    mdei.ThreadId = GetCurrentThreadId();
    mdei.ExceptionPointers = ep;
    mdei.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDump,
                      (MINIDUMP_TYPE)(MiniDumpWithDataSegs | MiniDumpWithThreadInfo |
                                      MiniDumpWithIndirectlyReferencedMemory |
                                      MiniDumpWithUnloadedModules | MiniDumpWithHandleData),
                      ep ? &mdei : nullptr, nullptr, nullptr);
    CloseHandle(hDump);
  }
  if (s_cleanupFileW[0]) DeleteFileW(s_cleanupFileW);

  // Best effort: also record in ShaderStress.log (may fail if the crash
  // happened while the log lock was held).
  g_App.quit = true;
  g_App.running = false;
  if (g_App.logMtx.try_lock()) {
    if (g_App.log.is_open()) {
      g_App.log << "[CRASH] see " << dir << "\n" << info;
      g_App.log.flush();
    }
    g_App.logMtx.unlock();
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

void InstallCrashHandlers() {
  SetUnhandledExceptionFilter(CrashFilter);
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
}
#else
static void CrashSignalHandler(int sig) {
  if (s_crashing.exchange(true)) _exit(128 + sig);
  const char *name = "UNKNOWN";
  switch (sig) {
  case SIGSEGV: name = "SIGSEGV"; break;
  case SIGFPE: name = "SIGFPE"; break;
  case SIGBUS: name = "SIGBUS"; break;
  case SIGILL: name = "SIGILL"; break;
  case SIGABRT: name = "SIGABRT"; break;
  }
  // snprintf is not formally async-signal-safe, but the process is already
  // lost and the buffer is on the stack; the information is worth the risk.
  char buf[1024];
  int n = snprintf(buf, sizeof(buf), "\n[CRASH] Signal: %s\n", name);
  if (n > 0 && (size_t)n < sizeof(buf))
    n += FormatJobContext(buf + n, sizeof(buf) - (size_t)n);
  if (n > 0) {
    ssize_t w = write(STDERR_FILENO, buf, (size_t)std::min<int>(n, (int)sizeof(buf) - 1));
    (void)w;
  }
  if (s_cleanupFileA[0]) unlink(s_cleanupFileA);
  _exit(128 + sig);
}

void InstallCrashHandlers() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_handler = CrashSignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESETHAND;
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGFPE, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);
  sigaction(SIGABRT, &sa, nullptr);
}
#endif
