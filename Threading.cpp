// Threading.cpp - Worker threads, IO stress, RAM stress, Dynamic mode, Watchdog
#include "Common.h"
using namespace std::chrono_literals;

#if !defined(PLATFORM_WINDOWS)
#include <signal.h>

thread_local int t_threadIdx = -1;
thread_local uint64_t t_lastSeed = 0;
thread_local int t_lastComplexity = 0;

static void crashHandler(int sig) {
  const char *name = "UNKNOWN";
  switch (sig) {
  case SIGSEGV: name = "SIGSEGV"; break;
  case SIGFPE:  name = "SIGFPE";  break;
  case SIGBUS:  name = "SIGBUS";  break;
  case SIGILL:  name = "SIGILL";  break;
  }

  // Async-signal-safe: only use write() and _exit()
  char buf[256];
  int len = 0;
  // Manual formatting (snprintf is NOT async-signal-safe)
  auto appendStr = [&](const char *s) {
    while (*s && len < 255) buf[len++] = *s++;
  };
  auto appendNum = [&](int64_t v) {
    if (v < 0) { buf[len++] = '-'; v = -v; }
    char tmp[20]; int tl = 0;
    if (v == 0) tmp[tl++] = '0';
    else while (v > 0) { tmp[tl++] = '0' + (v % 10); v /= 10; }
    for (int i = tl - 1; i >= 0 && len < 255; --i) buf[len++] = tmp[i];
  };
  auto appendU64 = [&](uint64_t v) {
    char tmp[20]; int tl = 0;
    if (v == 0) tmp[tl++] = '0';
    else while (v > 0) { tmp[tl++] = '0' + (v % 10); v /= 10; }
    for (int i = tl - 1; i >= 0 && len < 255; --i) buf[len++] = tmp[i];
  };

  appendStr("\n[CRASH] Signal: ");
  appendStr(name);
  appendStr(" | Thread: ");
  appendNum(t_threadIdx);
  appendStr(" | Seed: ");
  appendU64(t_lastSeed);
  appendStr(" | Complexity: ");
  appendNum(t_lastComplexity);
  appendStr("\nUse --repro ");
  appendU64(t_lastSeed);
  appendStr(" ");
  appendNum(t_lastComplexity);
  appendStr(" to reproduce.\n");
  buf[len] = '\0';

  write(STDERR_FILENO, buf, len);
  _exit(128 + sig);
}

void InstallCrashHandlers() {
  struct sigaction sa;
  sa.sa_handler = crashHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESETHAND; // One-shot to avoid infinite loops
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGFPE, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);
}
#endif // !PLATFORM_WINDOWS

// --- Worker Logic ---
static void RunCompilerLogic(int idx, Worker &w) {
  // Lightweight PRNG (XorShift64*) state per thread
  static thread_local uint64_t rngState = 0;
  if (rngState == 0) {
    // Seed with high-res tick mixed with thread ID
    uint64_t s = GetTick() + ((uint64_t)idx * 0x9E3779B97F4A7C15ULL);
    rngState = (s == 0) ? 1 : s;
  }

  auto NextRand = [&]() -> uint64_t {
    uint64_t x = rngState;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rngState = x;
    return x * 0x2545F4914F6CDD1DULL;
  };

  // Generate complexity: Exponential distribution approx
  // Range: ~5000 to ~500000 (capped to safe maximum)
  uint64_t r = NextRand();
  // Use log loading to simulate exponential-like distribution
  int complexity = 5000 + (int)(r % 10000);
  // Occasional spikes (capped to prevent overflow)
  if ((r & 0xF) == 0)
    complexity = std::min(complexity + (int)(r % 100000), 500000);
  if ((r & 0xFF) == 0)
    complexity = std::min(complexity + (int)(r % 400000), 500000);

  if (g_App.mode == 1) // Steady mode
    complexity = 12000;

  static thread_local uint64_t lastVer = 0;
  static thread_local StressConfig cachedCfg;

  // Per-job randomization of knobs (Simulation of varying shader
  // characteristics) We offset the global config slightly per job to create
  // "de-correlated" load
  StressConfig jobCfg;

  if (lastVer != g_ConfigVersion.load(std::memory_order_acquire)) {
    std::lock_guard<std::mutex> lk(g_ConfigMtx);
    cachedCfg = g_ActiveConfig;
    lastVer = g_ConfigVersion.load(std::memory_order_relaxed);
  }
  jobCfg = cachedCfg;

  // Apply micro-variation
  if (g_App.mode !=
      0) { // Don't randomize in benchmark mode if strictness is needed?
    // Actually, benchmark should be consistent?
    // Report says: "Randomize... per job... or periodically shuffle".
    // Let's vary intensity slightly if not steady mode?
    // For now, keep it simple: apply complexity variation.
    // Knobs:
    uint64_t r2 = NextRand();
    if ((r2 & 3) == 0)
      jobCfg.int_intensity =
          std::max(1, jobCfg.int_intensity + ((int)(r2 % 3) - 1));
    if ((r2 & 7) == 0)
      jobCfg.fma_intensity =
          std::max(1, jobCfg.fma_intensity + ((int)((r2 >> 4) % 3) - 1));
  }

  uint64_t seed =
      (uint64_t)GetTick() ^ ((uint64_t)idx << 32) ^
      (w.localShaders.load(std::memory_order_relaxed) * GOLDEN_RATIO);

#if !defined(PLATFORM_WINDOWS)
  t_lastSeed = seed;
  t_lastComplexity = complexity;
#endif
  SafeRunWorkload(seed, complexity, jobCfg, idx);
  uint64_t localCount = w.localShaders.fetch_add(1, std::memory_order_relaxed);

  // Periodic golden-value verification for CPU error detection.
  // Resolve the workload type ONCE so the dispatch and the expected-value
  // lookup are guaranteed to match (avoids a race if the user changes the
  // selected workload between two atomic reads).
  int mode = g_App.mode.load(std::memory_order_relaxed);
  const uint64_t verifyInterval = (mode == 0) ? 64ull : 128ull;
  const int verifyComplexity = VERIFY_COMPLEXITY;
  if (g_Golden.initialized && (localCount % verifyInterval) == 0) {
    StressConfig verifyCfg;
    verifyCfg.fma_intensity = 8;
    verifyCfg.int_intensity = 2;
    verifyCfg.div_intensity = 1;
    WorkloadType type = ResolveSelectedWorkload(g_App.selectedWorkload.load());
    uint64_t got;
    switch (type) {
    case WL_AVX512:  got = RunHyperStress_AVX512(42, verifyComplexity, verifyCfg); break;
    case WL_AVX2:    got = RunHyperStress_AVX2(42, verifyComplexity, verifyCfg);   break;
    case WL_SCALAR_SIM: got = RunRealisticCompilerSim_V3(42, verifyComplexity, verifyCfg); break;
    default:         got = RunHyperStress_Scalar(42, verifyComplexity, verifyCfg); break;
    }
    uint64_t expected = g_Golden.values[type];
    if (got != expected) {
      g_App.errors.fetch_add(1, std::memory_order_relaxed);
      g_App.Log(L"CPU ERROR detected on thread " + std::to_wstring(idx) +
                L" [" + GetResolvedISAName(type) + L"]" +
                L" (expected " + std::to_wstring(expected) + L", got " +
                std::to_wstring(got) + L")");
    }
  }
}

static void RunDecompressLogic(int idx, Worker &w) {
  const size_t BUF_SIZE = 512 * 1024;
  // Lazy heap allocation to avoid TLS bloat
  static thread_local std::vector<uint8_t> data;
  static thread_local std::mt19937 rng(idx * 777);
  static thread_local bool init = false;

  if (data.empty()) data.resize(BUF_SIZE);
  if (!init) {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (auto &b : data)
      b = (uint8_t)dist(rng);
    init = true;
  }

  uint64_t acc = 0;
  for (size_t i = 0; i < BUF_SIZE; i += 8) {
    uint8_t cmd = data[i] & 0x7;
    if (cmd < 3)
      acc = Rotl64(acc ^ data[i], 13);
    else if (cmd < 6) {
      size_t offset = (data[i + 1] << 8) | data[i + 2];
      offset &= (BUF_SIZE - 1);
      acc ^= data[offset];
    } else
      acc += 0xDEADBEEF;
    data[i] ^= (uint8_t)acc;
  }
}

void WorkerThread(int idx) {
  DisablePowerThrottling();
  PinThreadToCore(idx);
  SetFpuFlushMode();
#if !defined(PLATFORM_WINDOWS)
  t_threadIdx = idx;
#endif
  std::this_thread::sleep_for(std::chrono::milliseconds(idx * 5));
  auto &w = *g_Workers[idx];
  w.state.store(WorkerState::Running, std::memory_order_release);

  while (!w.terminate) {
    if (g_Repro.active) {
      StressConfig reproCfg;
      {
        std::lock_guard<std::mutex> lk(g_ConfigMtx);
        reproCfg = g_ActiveConfig;
      }
      SafeRunWorkload(g_Repro.seed, g_Repro.complexity, reproCfg, idx);
      return;
    }

    int numComp = g_App.activeCompilers.load(std::memory_order_relaxed);
    int numDec = g_App.activeDecomp.load(std::memory_order_relaxed);
    bool isComp = (idx < numComp);
    bool isDec = (!isComp && idx < (numComp + numDec));

    if (isComp)
      RunCompilerLogic(idx, w);
    else if (isDec)
      RunDecompressLogic(idx, w);
    else
      std::this_thread::sleep_for(10ms);

    w.lastTick = GetTick();
  }
  w.state.store(WorkerState::Stopped, std::memory_order_release);
}

// --- IO/RAM Stress (Cross-Platform) ---
#ifdef PLATFORM_WINDOWS

void IOThread(int ioIdx) {
  DisablePowerThrottling();
  SetFpuFlushMode();
  auto &w = *g_IOThreads[ioIdx];

  wchar_t path[MAX_PATH];
  GetTempPathW(MAX_PATH, path);
  std::wstring fpath =
      std::wstring(path) + L"stress_" + std::to_wstring(ioIdx) + L".tmp";

  bool fileCreated = false;
  HANDLE hFile = INVALID_HANDLE_VALUE;
  ScopedMem buf(IO_CHUNK_SIZE);
  std::mt19937_64 rng(GetTick() + ioIdx);

  while (!w.terminate) {
    if (!g_App.ioActive && !g_Repro.active) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    // Create temp file on first activation (deferred from startup)
    if (!fileCreated) {
      // Use CreateFileW to avoid narrow-string conversion (handles non-ASCII paths)
      HANDLE hCreate = CreateFileW(fpath.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (hCreate != INVALID_HANDLE_VALUE) {
        std::vector<char> junk(1024 * 1024, 'x');
        DWORD written;
        for (int i = 0; i < (IO_FILE_SIZE / (1024 * 1024)); ++i)
          WriteFile(hCreate, junk.data(), (DWORD)junk.size(), &written, nullptr);
        CloseHandle(hCreate);
      }

      hFile = CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
      fileCreated = true;
    }

    if (hFile == INVALID_HANDLE_VALUE) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }

    if (!buf) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    LARGE_INTEGER pos;
    pos.QuadPart = (rng() % (IO_FILE_SIZE - IO_CHUNK_SIZE)) & ~4095;
    SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN);

    DWORD read;
    uint8_t *p = buf.As<uint8_t>();
    if (ReadFile(hFile, p, (DWORD)IO_CHUNK_SIZE, &read, nullptr) && read > 0) {
      volatile uint8_t sink = p[0] ^ p[read - 1];
      (void)sink;
    }
    w.lastTick = GetTick();
  }

  if (hFile != INVALID_HANDLE_VALUE) {
    CloseHandle(hFile);
  }
  if (fileCreated) {
    DeleteFileW(fpath.c_str());
  }
}

void RAMThread() {
  DisablePowerThrottling();
  SetFpuFlushMode();
  auto &w = g_RAM;
  std::mt19937_64 rng(GetTick());

  while (!w.terminate) {
    if (!g_App.ramActive && !g_Repro.active) {
      std::this_thread::sleep_for(100ms);
      continue;
    }

    MEMORYSTATUSEX ms{sizeof(ms)};
    GlobalMemoryStatusEx(&ms);
    uint64_t safeSize =
        std::min<uint64_t>(ms.ullAvailPhys, ms.ullTotalPhys) * 7 / 10;
    if (safeSize > 16ull * 1024 * 1024 * 1024)
      safeSize = 16ull * 1024 * 1024 * 1024;
    safeSize &= ~4095;

    if (safeSize < 1024 * 1024) {
      std::this_thread::sleep_for(1s);
      continue;
    }

    ScopedMem mem(safeSize);
    if (mem.ptr) {
      uint64_t *p = mem.As<uint64_t>();
      size_t count = safeSize / sizeof(uint64_t);
      for (size_t i = 0; i < count; i += 16) {
        p[i] = (i + 16) % count;
      }

      uint64_t burstEnd = GetTick() + 5000;
      while (GetTick() < burstEnd && !w.terminate && g_App.ramActive) {
        if (rng() % 2 == 0) {
          size_t stride = 64;
          for (size_t i = 0; i < count; i += stride) {
            p[i] = (i + 16) % count;
          }
        } else {
          volatile uint64_t idx = 0;
          for (int k = 0; k < 100000; ++k) {
            idx = p[idx];
          }
        }
        w.lastTick = GetTick();
      }
    } else {
      std::this_thread::sleep_for(1s);
    }
  }
}

#else // Linux/macOS Implementation

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

void IOThread(int ioIdx) {
  SetFpuFlushMode();
  auto &w = *g_IOThreads[ioIdx];

  std::string fpath = "/tmp/stress_" + std::to_string(ioIdx) + ".tmp";

  bool fileCreated = false;
  int hFile = -1;
  ScopedMem buf(IO_CHUNK_SIZE);
  std::mt19937_64 rng(GetTick() + ioIdx);

  while (!w.terminate) {
    if (!g_App.ioActive && !g_Repro.active) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    // Create temp file on first activation (deferred from startup)
    if (!fileCreated) {
      std::ofstream f(fpath, std::ios::binary);
      std::vector<char> junk(1024 * 1024, 'x');
      for (int i = 0; i < (IO_FILE_SIZE / (1024 * 1024)); ++i)
        f.write(junk.data(), junk.size());
      f.close();

      // O_DIRECT is Linux specific, on macOS use F_NOCACHE
      int flags = O_RDONLY;
#ifdef PLATFORM_LINUX
      flags |= O_DIRECT;
#endif
      hFile = open(fpath.c_str(), flags);
#ifdef PLATFORM_MACOS
      if (hFile != -1)
        fcntl(hFile, F_NOCACHE, 1);
#endif
      fileCreated = true;
    }

    if (hFile == -1) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }

    if (!buf) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    off_t pos = (rng() % (IO_FILE_SIZE - IO_CHUNK_SIZE)) & ~4095;
    lseek(hFile, pos, SEEK_SET);

    uint8_t *p = buf.As<uint8_t>();
    ssize_t readBytes = read(hFile, p, IO_CHUNK_SIZE);
    if (readBytes > 0) {
      volatile uint8_t sink = p[0] ^ p[readBytes - 1];
      (void)sink;
    }
    w.lastTick = GetTick();
  }

  if (hFile != -1) {
    close(hFile);
  }
  if (fileCreated) {
    unlink(fpath.c_str());
  }
}

void RAMThread() {
  SetFpuFlushMode();
  auto &w = g_RAM;
  std::mt19937_64 rng(GetTick());

  while (!w.terminate) {
    if (!g_App.ramActive && !g_Repro.active) {
      std::this_thread::sleep_for(100ms);
      continue;
    }

    uint64_t availPhys = 0;
#ifdef PLATFORM_LINUX
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long pageSize = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && pageSize > 0)
      availPhys = (uint64_t)pages * (uint64_t)pageSize;
#elif defined(PLATFORM_MACOS)
    // macOS specific memory detection
    int mib[2];
    mib[0] = CTL_HW;
    mib[1] = HW_MEMSIZE;
    int64_t size = 0;
    size_t len = sizeof(size);
    if (sysctl(mib, 2, &size, &len, NULL, 0) == 0) {
      availPhys = (uint64_t)size;
    } else {
      availPhys = 8ULL * 1024 * 1024 * 1024; // Fallback
    }
#endif

    uint64_t safeSize = availPhys * 7 / 10;

    // Cap at 16GB like Windows
    if (safeSize > 16ull * 1024 * 1024 * 1024)
      safeSize = 16ull * 1024 * 1024 * 1024;

    // If detection failed (checks 0), default to 1GB to trigger stress anyway
    if (safeSize == 0)
      safeSize = 1024 * 1024 * 1024;

    safeSize &= ~4095;

    if (safeSize < 1024 * 1024) {
      std::this_thread::sleep_for(1s);
      continue;
    }

    ScopedMem mem(safeSize);
    if (mem.ptr) {
      uint64_t *p = mem.As<uint64_t>();
      size_t count = safeSize / sizeof(uint64_t);
      // Initialize to force OS to commit pages
      for (size_t i = 0; i < count; i += 512) {
        p[i] = (i + 16) % count;
      }

      uint64_t burstEnd = GetTick() + 5000;
      while (GetTick() < burstEnd && !w.terminate && g_App.ramActive) {
        if (rng() % 2 == 0) {
          size_t stride = 64;
          for (size_t i = 0; i < count; i += stride) {
            // Read/Write to properly dirty pages
            p[i] = (p[i] + 1);
          }
        } else {
          volatile uint64_t idx = 0;
          for (int k = 0; k < 100000; ++k) {
            idx = p[idx & (count - 1)]; // Safety mask
          }
        }
        w.lastTick = GetTick();
      }
    } else {
      std::this_thread::sleep_for(1s);
    }
  }
}

#endif // PLATFORM_WINDOWS

// Static storage for IO/RAM thread management to persist across calls
static std::vector<std::unique_ptr<ThreadWrapper>> s_IOThreadHandles;
static std::unique_ptr<ThreadWrapper> s_RAMThreadHandle;
static bool s_IOActive = false;
static bool s_RAMActive = false;
static std::mutex s_SetWorkMtx;  // Protects thread management

void SetWork(int requestComps, int requestDecomp, bool io, bool ram) {
  std::lock_guard<std::mutex> lock(s_SetWorkMtx);
  
  // Benchmark Mode Integrity: Force disable IO and RAM threads
  if (g_App.mode == 0) {
    io = false;
    ram = false;
  }
  
  // 1. Calculate Budget
  int cpuTotal = (int)g_Workers.size();
  int cntIO = io ? 1 : 0;
  int cntRAM = ram ? 1 : 0;
  int reserved = cntIO + cntRAM;
  int availableForWorkers = std::max(0, cpuTotal - reserved);

  // 2. Clamp Worker Counts to Available Budget
  if (requestComps > availableForWorkers)
    requestComps = availableForWorkers;
  if ((requestComps + requestDecomp) > availableForWorkers)
    requestDecomp = availableForWorkers - requestComps;

  g_App.activeCompilers = requestComps;
  g_App.activeDecomp = requestDecomp;

  // 3. Manage Worker Threads - Spawn all at startup, never join until shutdown
  // This avoids the expensive thread spawn/join cycle in dynamic mode
  int targetWorkers = availableForWorkers;
  int currentWorkers = (int)g_Threads.size();
  
  if (currentWorkers < targetWorkers) {
    // Only expand, never shrink during operation
    for (int i = currentWorkers; i < targetWorkers; ++i) {
      if (i < (int)g_Workers.size()) {
        g_Workers[i]->terminate = false;
        g_Workers[i]->state.store(WorkerState::Idle);
        auto t = std::make_unique<ThreadWrapper>();
        t->t = std::thread(WorkerThread, i);
        g_Threads.push_back(std::move(t));
      }
    }
  }
  // Note: We don't join threads when reducing count, just let them idle
  // The WorkerThread checks activeCompilers/activeDecomp to decide work

  // 4. Manage IO Thread (Single Thread)
  if (io && !s_IOActive) {
    g_IOThreads.clear();
    s_IOThreadHandles.clear();
    g_IOThreads.push_back(std::make_unique<Worker>());
    g_IOThreads[0]->terminate = false;
    auto t = std::make_unique<ThreadWrapper>();
    t->t = std::thread(IOThread, 0);
    s_IOThreadHandles.push_back(std::move(t));
    s_IOActive = true;
  } else if (!io && s_IOActive) {
    for (auto &w : g_IOThreads)
      w->terminate = true;
    for (auto &t : s_IOThreadHandles) {
      if (t && t->t.joinable()) {
        // Don't block here - let ThreadWrapper handle join in destructor
      }
    }
    s_IOThreadHandles.clear();
    g_IOThreads.clear();
    s_IOActive = false;
  }

  // 5. Manage RAM Thread
  if (ram && !s_RAMActive) {
    g_RAM.terminate = false;
    s_RAMThreadHandle = std::make_unique<ThreadWrapper>();
    s_RAMThreadHandle->t = std::thread(RAMThread);
    s_RAMActive = true;
  } else if (!ram && s_RAMActive) {
    g_RAM.terminate = true;
    s_RAMThreadHandle.reset();  // Let ThreadWrapper handle join
    s_RAMActive = false;
  }

  g_App.ioActive = io;
  g_App.ramActive = ram;
}

static void SmartSleep(int ms) {
  for (int i = 0; i < ms; i += 20) {
    if (!g_App.running || g_App.mode != 2)
      return;
    std::this_thread::sleep_for(20ms);
  }
}

// Apply Realistic configuration (only workload available)
void ApplyWorkloadConfig(int workloadSel) {
  (void)workloadSel;
  StressConfig cfg;
  
  // Realistic simulation - moderate intensity
  cfg.fma_intensity = 4;
  cfg.int_intensity = 4;
  cfg.div_intensity = 1;
  cfg.bit_intensity = 2;
  cfg.branch_intensity = 2;
  cfg.int_simd_intensity = 2;
  cfg.mem_pressure = 4;
  cfg.shuffle_freq = 8;
  cfg.cache_stride = 32768;
  cfg.name = L"Realistic";
  
  {
    std::lock_guard<std::mutex> lk(g_ConfigMtx);
    g_ActiveConfig = cfg;
    g_ConfigVersion.fetch_add(1, std::memory_order_release);
  }
}

void DynamicLoop() {
  DisablePowerThrottling();
  int cpu = (int)g_Workers.size();
  int pIdx = 0;
  struct {
    bool toggle2 = false;
    bool toggle4 = false;
  } state;

  auto SetStrict = [&](int c, int d, bool io, bool ram) {
    SetWork(c, d, io, ram);
  };
  std::mt19937 rng((unsigned)GetTick());
  const int PHASE_DURATION_MS = 10000;
  
  // Reset loop counter when starting
  g_App.loops = 0;

  while (g_App.running && g_App.mode == 2) {
    g_App.currentPhase = pIdx + 1;
    auto phaseStart = std::chrono::steady_clock::now();

    while (g_App.running && g_App.mode == 2) {
      auto now = std::chrono::steady_clock::now();
      if (std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                                phaseStart)
              .count() >= PHASE_DURATION_MS)
        break;

      switch (pIdx) {
      case 0:
        SetStrict(cpu, 0, false, false);
        SmartSleep(100);
        break;
      case 1:
        SetStrict(std::max(0, cpu - 4), 2, true, true);
        SmartSleep(100);
        break;
      case 2: {
        state.toggle2 = !state.toggle2;
        if (state.toggle2)
          SetStrict(0, 0, false, false);
        else
          SetStrict(std::max(0, cpu - 4), 2, true, true);
        SmartSleep(500);
      } break;
      case 3:
        SetStrict(0, std::max(0, cpu - 2), true, true);
        SmartSleep(100);
        break;
      case 4: {
        state.toggle4 = !state.toggle4;
        if (state.toggle4)
          SetStrict(0, 0, false, false);
        else
          SetStrict(0, std::max(0, cpu - 2), true, true);
        SmartSleep(500);
      } break;
      case 5:
        SetStrict(rng() % (cpu + 1), 0, false, false);
        SmartSleep(500);
        break;
      case 6: {
        bool io = rng() % 2;
        bool ram = rng() % 2;
        int avail = cpu;
        int d = (avail > 0) ? (rng() % (avail + 1)) : 0;
        SetStrict(0, d, io, ram);
        SmartSleep(500);
      } break;
      case 7:
        SetStrict(0, 1 + (rng() % 2), false, false);
        SmartSleep(500);
        break;
      case 8:
        SetStrict(1 + (rng() % 2), 0, false, false);
        SmartSleep(500);
        break;
      case 9: {
        bool io = rng() % 2;
        bool ram = rng() % 2;
        int c = rng() % (cpu + 1);
        int d = cpu - c;
        SetStrict(c, d, io, ram);
        SmartSleep(500);
      } break;
      case 10:
        SetStrict(cpu, 0, false, false);
        SmartSleep(200 + (rng() % 800));
        if (g_App.running && g_App.mode == 2) {
          SetStrict(0, 0, false, false);
          SmartSleep(300 + (rng() % 500));
        }
        break;
      case 11:
        SetStrict(cpu, 0, false, false);
        SmartSleep(100);
        if (g_App.running && g_App.mode == 2) {
          SetStrict(0, cpu, false, false);
          SmartSleep(100);
        }
        break;
      case 12: {
        SetStrict(cpu, 0, true, true);
        SmartSleep(50);
        SetStrict(0, 0, false, false);
        SmartSleep(50);
        break;
      }
      case 13: {
        for (int i = 0; i < cpu; i += 2) {
          SetStrict(2, 0, false, false);
          SmartSleep(100);
          if (!g_App.running || g_App.mode != 2)
            break;
        }
        break;
      }
      case 14: {
        int d = std::max(1, cpu - 2);
        SetStrict(0, d, true, true);
        SmartSleep(1000);
        break;
      }
      case 15: {
        // All threads at realistic intensity
        ApplyWorkloadConfig(0);
        SetStrict(cpu, 0, false, false);
        SmartSleep(1000);
        break;
      }
      }
    }
    pIdx = (pIdx + 1) % 16;  // Now 16 phases (0-15)
    if (pIdx == 0)
      g_App.loops++;
  }
}

void Watchdog() {
  DisablePowerThrottling();
  uint64_t runStart = 0;
  bool warmingUp = false, lastRunning = false;
  uint64_t benchIntervalStartShaders = 0;
  int lastBenchIntervalIndex = -1;
  uint64_t lastRateTime = GetTick();
  uint64_t lastRateShaders = 0;

  while (!g_App.quit) {
    bool currentRunning = g_App.running;
    uint64_t now = GetTick();
    uint64_t totalShaders = 0;
    for (const auto &w : g_Workers)
      totalShaders += w->localShaders.load(std::memory_order_relaxed);
    g_App.shaders = totalShaders;

    if (g_App.resetTimer.exchange(false)) {
      g_App.elapsed = 0;
      runStart = now;
      warmingUp = true;
      g_App.currentRate = 0;
      benchIntervalStartShaders = g_App.shaders;
      lastBenchIntervalIndex = -1;
      g_App.benchWinner = -1;
      g_App.benchComplete = false;
      for (int i = 0; i < 3; ++i)
        g_App.benchRates[i] = 0;
      lastRateTime = now;
      lastRateShaders = g_App.shaders;
    }

    if (currentRunning && !lastRunning) {
      // Starting fresh - reset everything
      g_App.resetTimer = true;
      g_App.benchComplete = false;
      g_App.benchWinner = -1;
      for (int i = 0; i < 3; ++i)
        g_App.benchRates[i] = 0;
    }
    lastRunning = currentRunning;

    if (currentRunning) {
      if (g_App.elapsed == 0 && runStart == 0) {
        runStart = now;
        benchIntervalStartShaders = g_App.shaders;
      }
      g_App.elapsed = (now - runStart) / 1000;

      if (warmingUp) {
        if (now - runStart > 2000) {
          warmingUp = false;
          lastRateTime = now;
          lastRateShaders = g_App.shaders;
        }
      } else if (now - lastRateTime >= 1000) {
        uint64_t current = g_App.shaders;
        uint64_t dt = now - lastRateTime;
        uint64_t dShader = current - lastRateShaders;
        if (dt > 0)
          g_App.currentRate = (dShader * 1000) / dt;
        lastRateTime = now;
        lastRateShaders = current;
      }

      if (g_App.mode == 0) {
        int currentIntervalIdx = (int)(g_App.elapsed / 60);
        if (currentIntervalIdx > lastBenchIntervalIndex) {
          if (lastBenchIntervalIndex >= 0 && lastBenchIntervalIndex < 3) {
            uint64_t diff = g_App.shaders - benchIntervalStartShaders;
            g_App.benchRates[lastBenchIntervalIndex] = diff / 60;
            benchIntervalStartShaders = g_App.shaders;

            // Generate/update hash after each interval (with zeros for
            // incomplete)
            uint64_t r0 = g_App.benchRates[0];
            uint64_t r1 = g_App.benchRates[1];
            uint64_t r2 = g_App.benchRates[2];
            std::wstring hash = GenerateBenchmarkHash(r0, r1, r2);
            g_App.SetBenchHash(hash);

            g_App.Log(L"Benchmark Minute " +
                      std::to_wstring(lastBenchIntervalIndex + 1) + L": " +
                      FmtNum(g_App.benchRates[lastBenchIntervalIndex]) +
                      L" Jobs/s | Hash: " + hash + L" (v" +
                      std::wstring(APP_VERSION) + L")");
          }
          lastBenchIntervalIndex = currentIntervalIdx;
        }

        if (g_App.elapsed >= BENCHMARK_DURATION_SEC && !g_App.benchComplete) {
          g_App.benchComplete = true;
          uint64_t r0 = g_App.benchRates[0], r1 = g_App.benchRates[1],
                   r2 = g_App.benchRates[2];

          if (r0 >= r1 && r0 >= r2)
            g_App.benchWinner = 0;
          else if (r1 >= r0 && r1 >= r2)
            g_App.benchWinner = 1;
          else
            g_App.benchWinner = 2;

          // Generate validation hash
          std::wstring finalHash = GenerateBenchmarkHash(r0, r1, r2);
          g_App.SetBenchHash(finalHash);

          std::wstringstream report;
          report << L"\n========================================\n";
          report << L"Shader Stress " << APP_VERSION << L" Benchmark Result\n";
#ifdef PLATFORM_WINDOWS
          report << L"OS: Windows | Arch: " << GetArchName() << L"\n";
#elif defined(PLATFORM_LINUX)
          report << L"OS: Linux | Arch: " << GetArchName() << L"\n";
#elif defined(PLATFORM_MACOS)
          report << L"OS: macOS | Arch: " << GetArchName() << L"\n";
#endif
          report << L"CPU: " << g_Cpu.brand << L"\n";
          report << L"Workload: "
                 << GetResolvedISAName(g_App.selectedWorkload.load()) << L"\n";
          report << L"----------------------------------------\n";
          report << L"Minute 1: " << FmtNum(r0) << L" Jobs/s\n";
          report << L"Minute 2: " << FmtNum(r1) << L" Jobs/s\n";
          report << L"Minute 3: " << FmtNum(r2) << L" Jobs/s\n";
          report << L"----------------------------------------\n";
          report << L"WINNER: Interval " << (g_App.benchWinner + 1) << L" ("
                 << FmtNum(g_App.benchRates[g_App.benchWinner])
                 << L" Jobs/s)\n";
          report << L"HASH: " << finalHash << L"\n";
          report << L"========================================";

          g_App.LogRaw(report.str());
          g_App.Log(L"Benchmark Finished. Hash: " + finalHash);

          // Auto-stop workers if checkbox is enabled
          if (g_App.autoStopBenchmark) {
            SetWork(0, 0, false, false);
            g_App.running = false;
            g_App.Log(L"Auto-stopped benchmark to reduce CPU load.");
          }

#ifdef PLATFORM_WINDOWS
          if (g_MainWindow)
            InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
        }
      }

      if (g_App.maxDuration.load() > 0 && runStart > 0) {
        if ((now - runStart) / 1000 >= g_App.maxDuration.load()) {
          g_App.running = false;
          g_App.quit = true;
          g_App.Log(L"Max duration reached. Stopping.");
#ifdef PLATFORM_WINDOWS
          if (g_MainWindow)
            InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
        }
      }
    } else {
      runStart = 0;
    }

    std::this_thread::sleep_for(500ms);
#ifdef PLATFORM_WINDOWS
    if (g_MainWindow && (g_App.running || g_App.benchComplete) &&
        !IsIconic(g_MainWindow))
      InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
  }
}
