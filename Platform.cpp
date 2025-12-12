// Platform.cpp - Cross-platform helpers (Windows/Linux/macOS)
#include "Common.h"

#ifdef PLATFORM_MACOS
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif

void DisablePowerThrottling() {
#ifdef PLATFORM_WINDOWS
  PROCESS_POWER_THROTTLING_STATE PowerThrottling = {0};
  PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
  PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
  PowerThrottling.StateMask = 0;
  SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling,
                       &PowerThrottling, sizeof(PowerThrottling));
#endif
  // Linux/macOS: No equivalent needed (no power throttling API)
}

void PinThreadToCore(int coreIdx) {
#ifdef PLATFORM_WINDOWS
  WORD groupCount = GetActiveProcessorGroupCount();
  if (groupCount > 1) {
    DWORD coresPerGroup = GetMaximumProcessorCount(0);
    WORD group = (WORD)(coreIdx / coresPerGroup);
    BYTE procIndex = (BYTE)(coreIdx % coresPerGroup);
    if (group < groupCount) {
      GROUP_AFFINITY affinity = {0};
      affinity.Group = group;
      affinity.Mask = (KAFFINITY)1 << procIndex;
      SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr);
      return;
    }
  }
  HANDLE hProc = GetCurrentProcess();
  DWORD_PTR processMask = 0, systemMask = 0;
  if (!GetProcessAffinityMask(hProc, &processMask, &systemMask) ||
      processMask == 0)
    return;

  int bitIndex = -1, foundCores = 0;
  for (int b = 0; b < (int)(sizeof(DWORD_PTR) * 8); ++b) {
    if (processMask & ((DWORD_PTR)1 << b)) {
      if (foundCores == coreIdx) {
        bitIndex = b;
        break;
      }
      ++foundCores;
    }
  }
  if (bitIndex >= 0)
    SetThreadAffinityMask(GetCurrentThread(), ((DWORD_PTR)1 << bitIndex));
#elif defined(PLATFORM_LINUX)
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(coreIdx, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#elif defined(PLATFORM_MACOS)
  thread_affinity_policy_data_t policy = {static_cast<integer_t>(coreIdx)};
  thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                    (thread_policy_t)&policy, THREAD_AFFINITY_POLICY_COUNT);
#endif
}

// Crash dump writing for debugging (Windows only)
#ifdef PLATFORM_WINDOWS
#include <dbghelp.h>
LONG WINAPI WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo, uint64_t seed,
                           int complexity, int threadIdx) {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::tm tm_buf;
  localtime_s(&tm_buf, &time);

  std::stringstream ss;
  ss << std::put_time(&tm_buf, "%Y-%m-%d_%H-%M-%S");
  std::string folderName =
      "Crash_" + ss.str() + "_Thread" + std::to_string(threadIdx);
  CreateDirectoryA(folderName.c_str(), nullptr);

  g_App.Log(L"CRASH DETECTED in Thread " + std::to_wstring(threadIdx) +
            L" | Seed: " + FmtNum(seed));

  std::string dumpPath = folderName + "\\crash.dmp";
  std::wstring dumpPathW(dumpPath.begin(), dumpPath.end());

  HANDLE hFile = CreateFileW(dumpPathW.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION mdei;
    mdei.ThreadId = GetCurrentThreadId();
    mdei.ExceptionPointers = pExceptionInfo;
    mdei.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                      (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
                                      MiniDumpWithHandleData |
                                      MiniDumpWithUnloadedModules),
                      &mdei, nullptr, nullptr);
    CloseHandle(hFile);
  }

  StressConfig cfgCopy;
  {
    std::lock_guard<std::mutex> lk(g_ConfigMtx);
    cfgCopy = g_ActiveConfig;
  }
  std::string infoPath = folderName + "\\crash_seed.txt";
  std::wofstream info(infoPath);
  info << L"Seed: " << seed << L"\nComplexity: " << complexity << L"\nThread: "
       << threadIdx << L"\n";
  info << L"CPU: " << g_Cpu.name << L" (" << g_Cpu.brand << L")\n";
  info << L"Config: " << cfgCopy.name << L"\n";
  info << L"App Version: " << APP_VERSION << L"\n";

  return EXCEPTION_EXECUTE_HANDLER;
}
#endif
