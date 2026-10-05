// Topology.cpp - Logical/physical CPU topology detection and thread pinning
#include "core/Topology.h"

#ifdef PLATFORM_LINUX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#endif
#ifdef PLATFORM_MACOS
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif

std::vector<int> BuildWorkerOrder(const std::vector<LogicalCpu> &cpus) {
  std::vector<int> order(cpus.size());
  for (size_t i = 0; i < cpus.size(); ++i)
    order[i] = (int)i;
  // Preference: fast cores first; within a performance class, every physical
  // core's primary thread before any SMT sibling; ties broken by core / LP.
  // Result on 8C/16T: CPU0,2,4,..,14 then 1,3,..,15. On hybrid parts the
  // P-core primaries come first, then P-core siblings, then E-cores.
  std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
    const LogicalCpu &x = cpus[(size_t)a], &y = cpus[(size_t)b];
    if (x.perfClass != y.perfClass) return x.perfClass > y.perfClass;
    if (x.smt != y.smt) return x.smt < y.smt;
    if (x.core != y.core) return x.core < y.core;
    return x.lp < y.lp;
  });
  return order;
}

std::vector<int> BuildCorePrimaryList(const std::vector<LogicalCpu> &cpus) {
  std::vector<int> order = BuildWorkerOrder(cpus);
  std::vector<int> primaries;
  std::vector<bool> seen;
  for (int idx : order) {
    int core = cpus[(size_t)idx].core;
    if (core < 0) continue;
    if ((size_t)core >= seen.size()) seen.resize((size_t)core + 1, false);
    if (seen[(size_t)core]) continue;
    seen[(size_t)core] = true;
    primaries.push_back(idx);
  }
  return primaries;
}

#ifdef PLATFORM_WINDOWS
static std::vector<LogicalCpu> DetectCpus(bool &pinning) {
  pinning = true;
  std::vector<LogicalCpu> cpus;
  DWORD len = 0;
  GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0)
    return cpus;
  std::vector<char> buf(len);
  auto *info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *>(buf.data());
  if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &len))
    return cpus;

  WORD groupCount = GetActiveProcessorGroupCount();
  std::vector<int> groupBase(groupCount + 1, 0);
  for (WORD g = 0; g < groupCount; ++g)
    groupBase[g + 1] = groupBase[g] + (int)GetMaximumProcessorCount(g);

  // Respect the process affinity mask (single-group case; multi-group
  // processes keep all CPUs of all groups).
  DWORD_PTR procMask = 0, sysMask = 0;
  bool haveMask = groupCount == 1 &&
                  GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) &&
                  procMask != 0;

  int coreIdx = 0;
  for (char *p = buf.data(); p < buf.data() + len;) {
    auto *cur = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *>(p);
    if (cur->Relationship == RelationProcessorCore) {
      int smt = 0;
      bool any = false;
      for (WORD g = 0; g < cur->Processor.GroupCount; ++g) {
        const GROUP_AFFINITY &ga = cur->Processor.GroupMask[g];
        for (int b = 0; b < (int)(sizeof(KAFFINITY) * 8); ++b) {
          if (!(ga.Mask & ((KAFFINITY)1 << b))) continue;
          if (haveMask && ga.Group == 0 && !(procMask & ((DWORD_PTR)1 << b))) {
            ++smt;
            continue;
          }
          LogicalCpu c;
          c.group = ga.Group;
          c.number = b;
          c.lp = (ga.Group < groupCount ? groupBase[ga.Group] : 0) + b;
          c.core = coreIdx;
          c.smt = smt++;
          // EfficiencyClass: higher value = more performant core.
          c.perfClass = cur->Processor.EfficiencyClass;
          cpus.push_back(c);
          any = true;
        }
      }
      if (any) ++coreIdx;
    }
    p += cur->Size;
  }
  return cpus;
}
#elif defined(PLATFORM_LINUX)
static bool ReadIntFile(const char *path, long &out) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  bool ok = fscanf(f, "%ld", &out) == 1;
  fclose(f);
  return ok;
}

// Parses a sysfs CPU list such as "0-7,16-23".
static std::vector<int> ReadCpuList(const char *path) {
  std::vector<int> out;
  FILE *f = fopen(path, "r");
  if (!f) return out;
  char line[4096];
  if (fgets(line, sizeof(line), f)) {
    char *s = line;
    while (*s) {
      char *end = nullptr;
      long a = strtol(s, &end, 10);
      if (end == s) break;
      long b = a;
      s = end;
      if (*s == '-') {
        ++s;
        b = strtol(s, &end, 10);
        s = end;
      }
      for (long i = a; i <= b && i < 65536; ++i) out.push_back((int)i);
      if (*s == ',') ++s;
      else break;
    }
  }
  fclose(f);
  return out;
}

static std::vector<LogicalCpu> DetectCpus(bool &pinning) {
  pinning = true;
  std::vector<LogicalCpu> cpus;
  cpu_set_t set;
  CPU_ZERO(&set);
  bool haveSet = sched_getaffinity(0, sizeof(set), &set) == 0;
  long n = sysconf(_SC_NPROCESSORS_CONF);
  if (n <= 0) n = 1;

  std::vector<int> pcores = ReadCpuList("/sys/devices/cpu_core/cpus");
  std::vector<int> ecores = ReadCpuList("/sys/devices/cpu_atom/cpus");

  // Map (package, core_id) -> dense core index.
  std::vector<std::pair<long, long>> coreKeys;
  for (long i = 0; i < n && i < CPU_SETSIZE; ++i) {
    if (haveSet && !CPU_ISSET((int)i, &set)) continue;
    char path[160];
    long coreId = i, pkg = 0, cap = 0;
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/topology/core_id", i);
    ReadIntFile(path, coreId);
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/topology/physical_package_id", i);
    ReadIntFile(path, pkg);
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/cpu_capacity", i);
    bool haveCap = ReadIntFile(path, cap);

    LogicalCpu c;
    c.lp = (int)i;
    c.number = (int)i;
    auto key = std::make_pair(pkg, coreId);
    auto it = std::find(coreKeys.begin(), coreKeys.end(), key);
    if (it == coreKeys.end()) {
      c.core = (int)coreKeys.size();
      coreKeys.push_back(key);
    } else {
      c.core = (int)(it - coreKeys.begin());
    }
    if (std::find(pcores.begin(), pcores.end(), (int)i) != pcores.end())
      c.perfClass = 1;
    else if (std::find(ecores.begin(), ecores.end(), (int)i) != ecores.end())
      c.perfClass = 0;
    else if (haveCap)
      c.perfClass = (int)cap;
    cpus.push_back(c);
  }
  // SMT index: order of appearance within each core.
  std::vector<int> perCore(coreKeys.size(), 0);
  for (auto &c : cpus)
    c.smt = perCore[(size_t)c.core]++;
  return cpus;
}
#else
static std::vector<LogicalCpu> DetectCpus(bool &pinning) {
  // macOS: no thread pinning API; expose logical CPUs for sizing only.
  pinning = false;
  std::vector<LogicalCpu> cpus;
  int logical = (int)std::thread::hardware_concurrency();
  if (logical <= 0) logical = 1;
  int physical = logical;
#ifdef PLATFORM_MACOS
  int v = 0;
  size_t sz = sizeof(v);
  if (sysctlbyname("hw.physicalcpu", &v, &sz, nullptr, 0) == 0 && v > 0)
    physical = v;
#endif
  int perCore = std::max(1, logical / std::max(1, physical));
  for (int i = 0; i < logical; ++i) {
    LogicalCpu c;
    c.lp = i;
    c.number = i;
    c.core = i / perCore;
    c.smt = i % perCore;
    cpus.push_back(c);
  }
  return cpus;
}
#endif

static CpuTopology BuildTopology() {
  CpuTopology t;
  bool pinning = true;
  t.cpus = DetectCpus(pinning);
  t.pinningSupported = pinning;
  if (t.cpus.empty()) {
    // Fallback: hardware_concurrency CPUs, no topology knowledge, no pinning.
    int n = (int)std::thread::hardware_concurrency();
    if (n <= 0) n = 4;
    for (int i = 0; i < n; ++i) {
      LogicalCpu c;
      c.lp = i;
      c.number = i;
      c.core = i;
      t.cpus.push_back(c);
    }
    t.pinningSupported = false;
  }
  int maxCore = -1, minClass = 1 << 30, maxClass = -1;
  for (const auto &c : t.cpus) {
    maxCore = std::max(maxCore, c.core);
    if (c.smt > 0) t.smt = true;
    minClass = std::min(minClass, c.perfClass);
    maxClass = std::max(maxClass, c.perfClass);
  }
  t.physicalCores = maxCore + 1;
  t.hybrid = minClass != maxClass;
  t.workerOrder = BuildWorkerOrder(t.cpus);
  t.corePrimary = BuildCorePrimaryList(t.cpus);
  return t;
}

const CpuTopology &GetTopology() {
  static const CpuTopology topo = BuildTopology();
  return topo;
}

int PinThreadToWorkerSlot(int workerIdx) {
  const CpuTopology &t = GetTopology();
  if (t.workerOrder.empty()) return -1;
  [[maybe_unused]] const LogicalCpu &c =
      t.cpus[(size_t)t.workerOrder[(size_t)workerIdx % t.workerOrder.size()]];
  if (!t.pinningSupported) return -1;
#ifdef PLATFORM_WINDOWS
  GROUP_AFFINITY ga{};
  ga.Group = (WORD)c.group;
  ga.Mask = (KAFFINITY)1 << c.number;
  if (!SetThreadGroupAffinity(GetCurrentThread(), &ga, nullptr)) {
    g_App.Log(L"Pinning failed for worker " + std::to_wstring(workerIdx) +
              L" -> " + DescribeLp(c.lp) + L" (error " +
              std::to_wstring(GetLastError()) + L")");
    return -1;
  }
  return c.lp;
#elif defined(PLATFORM_LINUX)
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(c.lp, &set);
  int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
  if (rc != 0) {
    g_App.Log(L"Pinning failed for worker " + std::to_wstring(workerIdx) +
              L" -> CPU " + std::to_wstring(c.lp) + L" (errno " +
              std::to_wstring(rc) + L")");
    return -1;
  }
  return c.lp;
#else
  return -1;
#endif
}

int CoreOfLp(int lp) {
  if (lp < 0) return -1;
  for (const auto &c : GetTopology().cpus)
    if (c.lp == lp) return c.core;
  return -1;
}

std::wstring DescribeLp(int lp) {
  if (lp < 0) return L"CPU ?";
  const CpuTopology &t = GetTopology();
  for (const auto &c : t.cpus) {
    if (c.lp != lp) continue;
    std::wstring s = L"CPU " + std::to_wstring(lp) + L" (core " +
                     std::to_wstring(c.core);
    if (t.smt) s += L", SMT " + std::to_wstring(c.smt);
    if (t.hybrid) s += L", class " + std::to_wstring(c.perfClass);
    return s + L")";
  }
  return L"CPU " + std::to_wstring(lp);
}

std::wstring TopologySummary() {
  const CpuTopology &t = GetTopology();
  std::wstring s = std::to_wstring(t.cpus.size()) + L" logical CPUs, " +
                   std::to_wstring(t.physicalCores) + L" cores" +
                   (t.smt ? L", SMT" : L"") + (t.hybrid ? L", hybrid" : L"") +
                   (t.pinningSupported ? L"" : L", no pinning");
  return s;
}

int WorkerSlotForCoreRank(int coreRank) {
  const CpuTopology &t = GetTopology();
  if (coreRank < 0 || (size_t)coreRank >= t.corePrimary.size()) return -1;
  int cpuIdx = t.corePrimary[(size_t)coreRank];
  for (size_t w = 0; w < t.workerOrder.size(); ++w)
    if (t.workerOrder[w] == cpuIdx) return (int)w;
  return -1;
}
