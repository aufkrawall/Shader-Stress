// CpuGuard.cpp - Refuses to start an x86-64-v3/v4 build on a CPU without the
// required instruction set, with a clear message instead of a silent
// STATUS_ILLEGAL_INSTRUCTION in a C++ static initializer.
//
// The check must run before any code compiled for the higher ISA level:
//  - Windows: custom PE entry point (build.py passes --entry) that runs before
//    the CRT and static constructors, then tail-calls the normal CRT entry.
//  - Linux: highest-priority ELF constructor.
// All guard code is compiled for baseline x86-64 via target("arch=x86-64") and
// uses inline asm for CPUID/XGETBV (no helper that could be compiled for v3/v4).
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__AVX2__) || defined(__AVX512F__)) && \
    (defined(__clang__) || defined(__GNUC__))

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#define SS_BASELINE __attribute__((target("arch=x86-64"), noinline))

namespace {
SS_BASELINE void Cpuid(unsigned leaf, unsigned sub, unsigned r[4]) {
  __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

SS_BASELINE unsigned long long Xgetbv0() {
  unsigned lo, hi;
  __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
  return ((unsigned long long)hi << 32) | lo;
}

// Returns true when the CPU and OS support everything this binary was built for.
SS_BASELINE bool CpuSupportsBuildLevel() {
  unsigned r[4];
  Cpuid(0, 0, r);
  const unsigned maxLeaf = r[0];
  if (maxLeaf < 7) return false;
  Cpuid(1, 0, r);
  const unsigned ecx1 = r[2];
  const bool osxsave = (ecx1 >> 27) & 1;
  if (!osxsave) return false;
  const unsigned long long xcr0 = Xgetbv0();
  // x86-64-v3: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE (+ OS YMM state).
  const bool v3cpu = ((ecx1 >> 28) & 1) && ((ecx1 >> 12) & 1) && ((ecx1 >> 22) & 1) &&
                     ((ecx1 >> 29) & 1);
  Cpuid(7, 0, r);
  const unsigned ebx7 = r[1];
  const bool v3leaf7 = ((ebx7 >> 5) & 1) && ((ebx7 >> 3) & 1) && ((ebx7 >> 8) & 1);
  Cpuid(0x80000001u, 0, r);
  const bool lzcnt = (r[2] >> 5) & 1;
  if (!(v3cpu && v3leaf7 && lzcnt && (xcr0 & 0x6) == 0x6)) return false;
#if defined(__AVX512F__)
  // x86-64-v4: AVX512F/BW/CD/DQ/VL (+ OS opmask/ZMM state).
  const bool v4 = ((ebx7 >> 16) & 1) && ((ebx7 >> 17) & 1) && ((ebx7 >> 28) & 1) &&
                  ((ebx7 >> 30) & 1) && ((ebx7 >> 31) & 1);
  if (!(v4 && (xcr0 & 0xE6) == 0xE6)) return false;
#endif
  return true;
}

#if defined(__AVX512F__)
#define SS_LEVEL_TEXT "x86-64-v4 (AVX-512)"
#else
#define SS_LEVEL_TEXT "x86-64-v3 (AVX2/FMA/BMI2)"
#endif
const char kMessageA[] =
    "This ShaderStress build requires an " SS_LEVEL_TEXT " CPU, which this system does not\n"
    "provide. Please use the plain x64 package (or x64-v3 for AVX2-capable CPUs).\n";
} // namespace

#if defined(_WIN32)
extern "C" int WinMainCRTStartup(void);
extern "C" int mainCRTStartup(void);

extern "C" SS_BASELINE int ShaderStressGuardedEntry(void) {
  if (!CpuSupportsBuildLevel()) {
    wchar_t flag[4];
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD type = (err && err != INVALID_HANDLE_VALUE) ? GetFileType(err) : FILE_TYPE_UNKNOWN;
    if (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK) {
      DWORD written = 0; // redirected stderr (scripts, CI)
      WriteFile(err, kMessageA, (DWORD)(sizeof(kMessageA) - 1), &written, nullptr);
    } else if (GetEnvironmentVariableW(L"SHADERSTRESS_CLI_LAUNCHER", flag, 4) > 0 &&
               AttachConsole(ATTACH_PARENT_PROCESS)) {
      HANDLE h = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
      if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(h, kMessageA, (DWORD)(sizeof(kMessageA) - 1), &written, nullptr);
        CloseHandle(h);
      }
    } else {
      MessageBoxA(nullptr, kMessageA, "ShaderStress - unsupported CPU", MB_OK | MB_ICONERROR);
    }
    ExitProcess(3);
  }
#if defined(SHADERSTRESS_CONSOLE_ENTRY)
  return mainCRTStartup();
#else
  return WinMainCRTStartup();
#endif
}
#else
__attribute__((constructor(101))) SS_BASELINE static void ShaderStressCpuGuard() {
  if (!CpuSupportsBuildLevel()) {
    ssize_t w = write(2, kMessageA, sizeof(kMessageA) - 1);
    (void)w;
    _exit(3);
  }
}
#endif

#endif
