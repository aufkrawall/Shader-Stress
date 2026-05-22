// CpuFeatures.cpp - CPU detection for x86 and ARM64
#include "Common.h"
#include <vector>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
// Helper with target attribute for safe XGETBV
#if defined(_MSC_VER)
static unsigned long long safe_xgetbv(unsigned int index) {
  return _xgetbv(index);
}
#elif defined(__clang__) || defined(__GNUC__)
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

#ifdef PLATFORM_WINDOWS
// Enumerate hybrid core topology via GetLogicalProcessorInformationEx.
// Populates CpuFeatures with P-core and E-core counts and returns
// vectors of logical processor indices for each type.
void EnumerateHybridTopology(CpuFeatures &f) {
  f.numPcores = 0;
  f.numEcores = 0;
  if (!f.isHybrid)
    return;

  DWORD returnLength = 0;
  GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &returnLength);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || returnLength == 0)
    return;

  std::vector<char> buf(static_cast<size_t>(returnLength));
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *info =
      reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buf.data());

  if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &returnLength))
    return;

  char *ptr = buf.data();
  while (ptr < buf.data() + returnLength) {
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *current =
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(ptr);
    if (current->Relationship == RelationProcessorCore) {
      // Intel/AMD document: higher efficiency class = more performant core (P-core).
      // EfficiencyClass 0 = E-core (efficient), class 1+ = P-core (performance).
      BYTE effClass = current->Processor.EfficiencyClass;
      if (effClass == 0)
        f.numEcores++;
      else
        f.numPcores++;
    }
    ptr += current->Size;
  }
}
#elif defined(PLATFORM_LINUX)
// Linux: read core_cpus from sysfs to distinguish P-cores from E-cores.
// /sys/devices/system/cpu/cpu*/topology/core_cpu_list lists CPUs sharing a core.
// /sys/devices/system/cpu/cpu*/topology/core_type (if available) distinguishes.
// Fallback: if isHybrid but cannot enumerate, assume 50/50 split.
void EnumerateHybridTopology(CpuFeatures &f) {
  f.numPcores = 0;
  f.numEcores = 0;
  if (!f.isHybrid)
    return;

  // Try reading package_cpus for total count and core_cpus for SMT topology.
  // If hybrid, the kernel exposes /sys/devices/system/cpu/cpu*/topology/core_type
  FILE *cpuTop = fopen("/sys/devices/system/cpu/cpu0/topology/core_type", "r");
  if (cpuTop) {
    // core_type file exists; enumerate all CPUs
    char line[64];
    while (fgets(line, sizeof(line), cpuTop)) {
      // Each line: cpu_id core_type_id (e.g. "0 0" for P-core, "1 1" for E-core)
      int cpuIdx, type;
      if (sscanf(line, "%d %d", &cpuIdx, &type) == 2) {
        if (type == 0)
          f.numPcores++;
        else
          f.numEcores++;
      }
    }
    fclose(cpuTop);
  }

  // If sysfs enumeration failed, fall back: iterate all present CPUs and use
  // cpuinfo_max_freq as a heuristic (P-cores typically have higher max freq).
  if (f.numPcores == 0 && f.numEcores == 0) {
    long numCPUs = sysconf(_SC_NPROCESSORS_CONF);
    for (long i = 0; i < numCPUs; ++i) {
      char path[128];
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%ld/cpufreq/cpuinfo_max_freq", i);
      FILE *freqFile = fopen(path, "r");
      if (freqFile) {
        unsigned long freq = 0;
        if (fscanf(freqFile, "%lu", &freq) == 1) {
          // Rough heuristic: freq above median is P-core candidate
          // We just count total CPUs and assume ~half are P-cores
          (void)freq; // use in more refined heuristic if needed
        }
        fclose(freqFile);
      }
    }
    // Fallback split: assume performance cores are the first half
    f.numPcores = (int)(numCPUs / 2);
    if (f.numPcores < 1) f.numPcores = 1;
    f.numEcores = (int)(numCPUs - f.numPcores);
  }
}
#else
// macOS: No hybrid CPU topology on Apple Silicon (all performance cores).
void EnumerateHybridTopology(CpuFeatures &f) {
  f.numPcores = 0;
  f.numEcores = 0;
  (void)f;
}
#endif

std::wstring GetCpuBrand() {
#if defined(_M_ARM64) || defined(__aarch64__)
  return L"ARM64 Processor";
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||           \
    defined(_M_IX86)
  unsigned int eax, ebx, ecx, edx;
  char brand[48] = {0};

  if (__get_cpuid(0x80000000, &eax, &ebx, &ecx, &edx) && eax >= 0x80000004) {
    unsigned int buf[12];
    __get_cpuid(0x80000002, &buf[0], &buf[1], &buf[2], &buf[3]);
    __get_cpuid(0x80000003, &buf[4], &buf[5], &buf[6], &buf[7]);
    __get_cpuid(0x80000004, &buf[8], &buf[9], &buf[10], &buf[11]);
    std::memcpy(&brand[0], buf, sizeof(buf));
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
  f.isHybrid = false;
  f.family = 0;
  f.model = 0;
  f.numPcores = 0;
  f.numEcores = 0;
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
  // Decode family/model from CPUID leaf 1 signature (EAX).
  // This follows Intel/AMD architectural encoding and avoids vendor-string
  // dependency mistakes.
  if (maxFunc >= 1) {
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    const unsigned int signature = eax;
    const unsigned int baseFamily = (signature >> 8) & 0xF;
    const unsigned int baseModel = (signature >> 4) & 0xF;
    const unsigned int extFamily = (signature >> 20) & 0xFF;
    const unsigned int extModel = (signature >> 16) & 0xF;
    f.family =
        (baseFamily == 0xF) ? (int)(baseFamily + extFamily) : (int)baseFamily;
    f.model = (int)baseModel;
    if (baseFamily == 0x6 || baseFamily == 0xF)
      f.model |= (int)(extModel << 4);
    
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
          f.isHybrid = (edx & (1 << 15)) != 0;

          if (f.hasAVX512F && (xcr0 & 0xE0) != 0xE0)
            f.hasAVX512F = false;
        }
      }
    }

    // Detect hybrid core topology (Intel hybrid: Alder Lake+).
    // Per-thread core type detection is done in PinThreadToCore.
    // Here we just mark that the CPU has hybrid topology.
  }

  // Enumerate P-core / E-core topology on hybrid CPUs
  EnumerateHybridTopology(f);

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
