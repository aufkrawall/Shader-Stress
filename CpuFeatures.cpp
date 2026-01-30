// CpuFeatures.cpp - CPU detection for x86 and ARM64
#include "Common.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
// Helper with target attribute for safe XGETBV
#if defined(__clang__) || defined(__GNUC__)
__attribute__((target("xsave"))) static unsigned long long
safe_xgetbv(unsigned int index) {
  return _xgetbv(index);
}
#else
static unsigned long long safe_xgetbv(unsigned int index) {
  return _xgetbv(index);
}
#endif
#endif

std::wstring GetCpuBrand() {
#if defined(_M_ARM64) || defined(__aarch64__)
  return L"ARM64 Processor";
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||           \
    defined(_M_IX86)
  unsigned int eax, ebx, ecx, edx;
  char brand[48] = {0};

  if (__get_cpuid(0x80000000, &eax, &ebx, &ecx, &edx) && eax >= 0x80000004) {
    __get_cpuid(0x80000002, (unsigned int *)&brand[0],
                (unsigned int *)&brand[4], (unsigned int *)&brand[8],
                (unsigned int *)&brand[12]);
    __get_cpuid(0x80000003, (unsigned int *)&brand[16],
                (unsigned int *)&brand[20], (unsigned int *)&brand[24],
                (unsigned int *)&brand[28]);
    __get_cpuid(0x80000004, (unsigned int *)&brand[32],
                (unsigned int *)&brand[36], (unsigned int *)&brand[40],
                (unsigned int *)&brand[44]);
  }

  std::string s(brand);
  s.erase(std::unique(s.begin(), s.end(),
                      [](char a, char b) { return a == ' ' && b == ' '; }),
          s.end());
  if (!s.empty() && s[0] == ' ')
    s.erase(0, 1);
  if (s.empty())
    return L"Unknown CPU";
  return std::wstring(s.begin(), s.end());
#else
  return L"Unknown Processor";
#endif
}

CpuFeatures GetCpuInfo() {
  CpuFeatures f;
  f.brand = GetCpuBrand();
  f.hasAVX2 = false;
  f.hasAVX512F = false;
  f.hasFMA = false;
  f.family = 0;
  f.model = 0;
  f.name = L"Scalar";

#if defined(_M_ARM64) || defined(__aarch64__)
  f.hasFMA = true;
  f.name = L"ARM64";
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||           \
    defined(_M_IX86)
  unsigned int eax, ebx, ecx, edx;

  if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx))
    return f;

  unsigned int maxFunc = eax;

  // Detect CPU family and model for tuning
  // Intel signature: ebx = vendor (GenuineIntel=0x756E6547)
  // AMD signature: ebx = vendor (AuthenticAMD=0x68747541)
  if (maxFunc >= 1) {
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    f.family = (eax >> 8) & 0xF;
    f.model = ((eax >> 12) & 0xF0) | ((eax >> 4) & 0xF);
    
    // Extended family for AMD
    if (ebx == 0x68747541 || ebx == 0x69746E65 || ebx == 0x746E6541) {
      // AMD signature detected
      unsigned int eax_ext;
      if (__get_cpuid(0x80000000, &eax_ext, &ebx, &ecx, &edx) && eax_ext >= 0x80000001) {
        unsigned int extFamily = (eax_ext >> 20) & 0xFF;
        f.family += extFamily;  // Extended family
      }
    }
    
    f.hasFMA = (ecx & (1 << 12)) != 0;
    bool osxsave = (ecx & (1 << 27)) != 0;
    bool cpuAVX = (ecx & (1 << 28)) != 0;

    if (osxsave && cpuAVX) {
      unsigned long long xcr0 = safe_xgetbv(0);

      if ((xcr0 & 0x6) == 0x6) {
        if (maxFunc >= 7) {
          __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
          f.hasAVX2 = (ebx & (1 << 5)) != 0;
          f.hasAVX512F = (ebx & (1 << 16)) != 0;

          if (f.hasAVX512F && (xcr0 & 0xE0) != 0xE0)
            f.hasAVX512F = false;
        }
      }
    }
  }

  if (f.hasAVX512F)
    f.name = L"AVX-512";
  else if (f.hasAVX2 && f.hasFMA)
    f.name = L"AVX2";
  else if (f.hasFMA)
    f.name = L"FMA";
  else
    f.name = L"Scalar";
#endif
  return f;
}
