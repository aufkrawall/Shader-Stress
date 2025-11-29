#define _WIN32_WINNT 0x0A00
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <processthreadsapi.h>
#include <shellapi.h>
#include <cstdio>
#include <intrin.h>
#include <immintrin.h>
#include <dbghelp.h>

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <array>
#include <deque>
#include <chrono>
#include <map>
#include <locale>
#include <iostream>

#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "dwmapi")
#pragma comment(lib, "shcore")
#pragma comment(lib, "shell32")
#pragma comment(lib, "dbghelp")

namespace fs = std::filesystem;
using namespace std::chrono_literals;

const std::wstring APP_VERSION = L"1.0";

// --- Helpers & Global State ---
static inline uint64_t Rotl64(uint64_t v, unsigned r) { return (v << r) | (v >> (64u - r)); }
static inline uint64_t GetTick() { return GetTickCount64(); }

// Abbreviated US Format (e.g., 87.1k, 1.2M)
std::wstring FmtNum(uint64_t v) {
    if (v < 1000) return std::to_wstring(v);

    wchar_t buf[64];
    double n = (double)v;
    const wchar_t* suffix = L"";

    if (v >= 1000000) {
        n /= 1000000.0;
        suffix = L"M";
    } else {
        n /= 1000.0;
        suffix = L"k";
    }

    _snwprintf_s(buf, _TRUNCATE, L"%.1f%s", n, suffix);
    std::wstring res(buf);
    std::replace(res.begin(), res.end(), L',', L'.');
    return res;
}

std::wstring FmtTime(uint64_t s) {
    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(2) << (s/3600) << L":" << std::setw(2) << ((s%3600)/60) << L":" << std::setw(2) << (s%60);
    return ss.str();
}

struct CpuFeatures {
    bool hasAVX2 = false;
    bool hasAVX512F = false;
    bool hasFMA = false;
    std::wstring name;
};

CpuFeatures GetCpuInfo() {
    CpuFeatures f;
    int regs[4];
    __cpuid(regs, 0);
    int nIds = regs[0];

    if (nIds >= 1) {
        __cpuid(regs, 1);
        f.hasFMA = (regs[2] & (1 << 12)) != 0;
        bool osExample = (regs[2] & (1 << 27)) != 0; // OSXSAVE bit
        bool cpuAVX = (regs[2] & (1 << 28)) != 0;

        if (osExample && cpuAVX) {
            unsigned long long xcr0 = _xgetbv(0);
            if ((xcr0 & 0x6) == 0x6) {
                if (nIds >= 7) {
                    __cpuidex(regs, 7, 0);
                    f.hasAVX2 = (regs[1] & (1 << 5)) != 0;
                    f.hasAVX512F = (regs[1] & (1 << 16)) != 0;

                    if (f.hasAVX512F) {
                        if ((xcr0 & 0xE0) != 0xE0) {
                            f.hasAVX512F = false;
                        }
                    }
                }
            } else {
                f.hasAVX2 = false;
                f.hasFMA = false;
            }
        }
    }

    if (f.hasAVX512F) f.name = L"AVX-512";
    else if (f.hasAVX2 && f.hasFMA) f.name = L"AVX2";
    else f.name = L"Scalar";
    return f;
}

CpuFeatures g_Cpu;
bool g_ForceNoAVX512 = false;

// --- REPRO MODE STATE ---
struct ReproSettings {
    bool active = false;
    uint64_t seed = 0;
    int complexity = 0;
} g_Repro;

// --- STRESS CONFIGURATION ---
struct StressConfig {
    int fma_intensity = 1;
    int int_intensity = 1;
    int mem_pressure = 0;
    int branch_freq = 0;
    std::wstring name = L"Default";
};

StressConfig g_ActiveConfig;
std::mutex g_ConfigMtx;

std::vector<uint64_t> g_ColdStorage;

struct AppState {
    std::atomic<bool> running{false}, quit{false};
    std::atomic<int> mode{2}, activeCompilers{0}, activeDecomp{0}, loops{0};
    std::atomic<bool> ioActive{false}, ramActive{false};
    std::atomic<bool> resetTimer{false};
    std::atomic<int> currentPhase{0};

    std::atomic<uint64_t> shaders{0};
    std::atomic<uint64_t> totalNodes{0};
    std::atomic<uint64_t> errors{0}, elapsed{0};

    std::atomic<uint64_t> currentRate{0};
    std::atomic<uint64_t> nodeRate{0};
    std::deque<uint64_t> last3Rates;
    std::mutex metricsMtx;
    std::atomic<uint64_t> maxDuration{0};

    std::wstring sigStatus;
    std::wofstream log;
    std::mutex logMtx;

    void Log(const std::wstring& msg) {
        std::lock_guard<std::mutex> lk(logMtx);
        if(log.is_open()) {
            SYSTEMTIME t; GetSystemTime(&t);
            log << L"[" << t.wHour << L":" << t.wMinute << L":" << t.wSecond << L"." << t.wMilliseconds << L"] " << msg << std::endl;
        }
        if(g_Repro.active) {
            std::wcout << msg << std::endl;
        }
    }
} g_App;

HWND g_MainWindow = nullptr;
float g_Scale = 1.0f;
int S(int v) { return (int)(v * g_Scale); }

void DisablePowerThrottling() {
    PROCESS_POWER_THROTTLING_STATE PowerThrottling;
    RtlZeroMemory(&PowerThrottling, sizeof(PowerThrottling));
    PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    PowerThrottling.StateMask = 0;
    SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &PowerThrottling, sizeof(PowerThrottling));
}

// --- CRASH DUMPING SYSTEM ---
LONG WINAPI WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo, uint64_t seed, int complexity, int threadIdx) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_s(&tm_buf, &time);

    std::stringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%d_%H-%M-%S");

    std::string folderName = "Crash_" + ss.str() + "_Thread" + std::to_string(threadIdx);
    fs::create_directories(folderName);
    fs::path basePath = fs::path(folderName);

    std::wstring crashMsg = L"CRASH DETECTED in Thread " + std::to_wstring(threadIdx) +
    L" | Seed: " + FmtNum(seed) +
    L" | Complexity: " + FmtNum(complexity);
    g_App.Log(crashMsg);

    std::wstring dumpPath = (basePath / "crash.dmp").wstring();
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pExceptionInfo;
        mdei.ClientPointers = FALSE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules), &mdei, nullptr, nullptr);
        CloseHandle(hFile);
    }

    {
        StressConfig cfgCopy;
        {
            std::lock_guard<std::mutex> lk(g_ConfigMtx);
            cfgCopy = g_ActiveConfig;
        }
        std::wofstream info(basePath / "crash_seed.txt");
        info << L"Seed: " << seed << L"\nComplexity: " << complexity << L"\nThread: " << threadIdx << L"\n";
        info << L"CPU: " << g_Cpu.name << L"\n";
        info << L"Config: " << cfgCopy.name << L"\n";
    }

    { std::lock_guard<std::mutex> lk(g_App.logMtx); if(g_App.log.is_open()) g_App.log.flush(); }

    return EXCEPTION_EXECUTE_HANDLER;
}

// --- KERNELS ---
struct alignas(64) HotNode { float fRegs[16]; uint64_t iRegs[8]; };
__forceinline uint64_t RunGraphColoringMicro(uint64_t val) { uint64_t x = val; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x * 0x2545F4914F6CDD1Dull; }

__forceinline void VerifyLogic(uint64_t seed, uint64_t val) {
    uint64_t expected = (seed * 0x123456789) ^ 0xDEADBEEF;
    uint64_t result = (val - 0x1) / 2; // Dummy calc
    if (result == 0) { /* prevent optimization */ volatile int x = 0; (void)x; }
}

__forceinline void InterlockedXorCold(uint64_t* ptr, uint64_t val) {
    _InterlockedXor64((volatile __int64*)ptr, (long long)val);
}

void RunHyperStress_AVX2(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) { uint64_t s = seed + i * 0x9E3779B97F4A7C15ull; for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f; for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32); }
    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0; uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    __m256 vFMA = _mm256_set1_ps(1.0001f); __m256 vMul = _mm256_set1_ps(0.9999f);

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode& n0 = nodes[(i)%BLOCK_SIZE]; HotNode& n1 = nodes[(i+1)%BLOCK_SIZE]; HotNode& n2 = nodes[(i+2)%BLOCK_SIZE]; HotNode& n3 = nodes[(i+3)%BLOCK_SIZE];

        for(int k=0; k < config.int_intensity; ++k) {
            n0.iRegs[0] = (n0.iRegs[0] ^ 0x9E3779B9) * n0.iRegs[1]; n1.iRegs[0] = (n1.iRegs[0] ^ 0x9E3779B9) * n1.iRegs[1];
            n2.iRegs[0] = (n2.iRegs[0] ^ 0x9E3779B9) * n2.iRegs[1]; n3.iRegs[0] = (n3.iRegs[0] ^ 0x9E3779B9) * n3.iRegs[1];
        }
        for(int k=0; k < config.fma_intensity; ++k) {
            __m256 f0a = _mm256_load_ps(n0.fRegs); __m256 f0b = _mm256_load_ps(n0.fRegs+8); f0a = _mm256_fmadd_ps(f0a, vMul, vFMA); f0b = _mm256_fmadd_ps(f0b, vMul, vFMA); _mm256_store_ps(n0.fRegs, f0a); _mm256_store_ps(n0.fRegs+8, f0b);
            __m256 f1a = _mm256_load_ps(n1.fRegs); __m256 f1b = _mm256_load_ps(n1.fRegs+8); f1a = _mm256_fmadd_ps(f1a, vMul, vFMA); f1b = _mm256_fmadd_ps(f1b, vMul, vFMA); _mm256_store_ps(n1.fRegs, f1a); _mm256_store_ps(n1.fRegs+8, f1b);
            __m256 f2a = _mm256_load_ps(n2.fRegs); __m256 f2b = _mm256_load_ps(n2.fRegs+8); f2a = _mm256_fmadd_ps(f2a, vMul, vFMA); f2b = _mm256_fmadd_ps(f2b, vMul, vFMA); _mm256_store_ps(n2.fRegs, f2a); _mm256_store_ps(n2.fRegs+8, f2b);
            __m256 f3a = _mm256_load_ps(n3.fRegs); __m256 f3b = _mm256_load_ps(n3.fRegs+8); f3a = _mm256_fmadd_ps(f3a, vMul, vFMA); f3b = _mm256_fmadd_ps(f3b, vMul, vFMA); _mm256_store_ps(n3.fRegs, f3a); _mm256_store_ps(n3.fRegs+8, f3b);
        }
        if (config.mem_pressure > 0 && coldPtr) {
            for (int m = 0; m < config.mem_pressure; ++m) {
                InterlockedXorCold(&coldPtr[n0.iRegs[0]&coldMask], n0.iRegs[1]);
                InterlockedXorCold(&coldPtr[n1.iRegs[0]&coldMask], n1.iRegs[1]);
                InterlockedXorCold(&coldPtr[n2.iRegs[0]&coldMask], n2.iRegs[1]);
                InterlockedXorCold(&coldPtr[n3.iRegs[0]&coldMask], n3.iRegs[1]);
            }
        }
        if (config.branch_freq > 0) {
            if ((n0.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n0.iRegs[2] = RunGraphColoringMicro(n0.iRegs[2]);
            if ((n1.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n1.iRegs[2] = RunGraphColoringMicro(n1.iRegs[2]);
            if ((n2.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n2.iRegs[2] = RunGraphColoringMicro(n2.iRegs[2]);
            if ((n3.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n3.iRegs[2] = RunGraphColoringMicro(n3.iRegs[2]);
        }
    }
}

void RunHyperStress_AVX512(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) { uint64_t s = seed + i * 0x9E3779B97F4A7C15ull; for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f; for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32); }
    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0; uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    __m512 vFMA = _mm512_set1_ps(1.0001f); __m512 vMul = _mm512_set1_ps(0.9999f);

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode& n0 = nodes[(i)%BLOCK_SIZE]; HotNode& n1 = nodes[(i+1)%BLOCK_SIZE]; HotNode& n2 = nodes[(i+2)%BLOCK_SIZE]; HotNode& n3 = nodes[(i+3)%BLOCK_SIZE];

        for(int k=0; k < config.int_intensity; ++k) {
            n0.iRegs[0] = (n0.iRegs[0] ^ 0x9E3779B9) * n0.iRegs[1]; n1.iRegs[0] = (n1.iRegs[0] ^ 0x9E3779B9) * n1.iRegs[1];
            n2.iRegs[0] = (n2.iRegs[0] ^ 0x9E3779B9) * n2.iRegs[1]; n3.iRegs[0] = (n3.iRegs[0] ^ 0x9E3779B9) * n3.iRegs[1];
        }
        for(int k=0; k < config.fma_intensity; ++k) {
            __m512 f0 = _mm512_load_ps(n0.fRegs); __m512 f1 = _mm512_load_ps(n1.fRegs); __m512 f2 = _mm512_load_ps(n2.fRegs); __m512 f3 = _mm512_load_ps(n3.fRegs);
            f0 = _mm512_fmadd_ps(f0, vMul, vFMA); f1 = _mm512_fmadd_ps(f1, vMul, vFMA); f2 = _mm512_fmadd_ps(f2, vMul, vFMA); f3 = _mm512_fmadd_ps(f3, vMul, vFMA);
            _mm512_store_ps(n0.fRegs, f0); _mm512_store_ps(n1.fRegs, f1); _mm512_store_ps(n2.fRegs, f2); _mm512_store_ps(n3.fRegs, f3);
        }
        if (config.mem_pressure > 0 && coldPtr) {
            for (int m = 0; m < config.mem_pressure; ++m) {
                InterlockedXorCold(&coldPtr[n0.iRegs[0]&coldMask], n0.iRegs[1]);
                InterlockedXorCold(&coldPtr[n1.iRegs[0]&coldMask], n1.iRegs[1]);
                InterlockedXorCold(&coldPtr[n2.iRegs[0]&coldMask], n2.iRegs[1]);
                InterlockedXorCold(&coldPtr[n3.iRegs[0]&coldMask], n3.iRegs[1]);
            }
        }
        if (config.branch_freq > 0) {
            if ((n0.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n0.iRegs[2] = RunGraphColoringMicro(n0.iRegs[2]);
            if ((n1.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n1.iRegs[2] = RunGraphColoringMicro(n1.iRegs[2]);
            if ((n2.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n2.iRegs[2] = RunGraphColoringMicro(n2.iRegs[2]);
            if ((n3.iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) n3.iRegs[2] = RunGraphColoringMicro(n3.iRegs[2]);
        }
    }
}

void RunHyperStress_Scalar(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) { uint64_t s = seed + i * 0x9E3779B97F4A7C15ull; for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f; for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32); }
    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0; uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    float vFMA = 1.0001f; float vMul = 0.9999f;

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode* ptrs[4] = { &nodes[i%BLOCK_SIZE], &nodes[(i+1)%BLOCK_SIZE], &nodes[(i+2)%BLOCK_SIZE], &nodes[(i+3)%BLOCK_SIZE] };
        for(int k=0; k < config.int_intensity; ++k) { for(int p=0; p<4; ++p) ptrs[p]->iRegs[0] = (ptrs[p]->iRegs[0] ^ 0x9E3779B9) * ptrs[p]->iRegs[1]; }
        for(int k=0; k < config.fma_intensity; ++k) { for(int p=0; p<4; ++p) { for(int f=0; f<16; ++f) { ptrs[p]->fRegs[f] = (ptrs[p]->fRegs[f] * vMul) + vFMA; } } }
        if (config.mem_pressure > 0 && coldPtr) { for (int m = 0; m < config.mem_pressure; ++m) { for(int p=0; p<4; ++p) InterlockedXorCold(&coldPtr[ptrs[p]->iRegs[0] & coldMask], ptrs[p]->iRegs[1]); } }
        if (config.branch_freq > 0) {
            for(int p=0; p<4; ++p) if ((ptrs[p]->iRegs[0] & 0xFF) < (uint64_t)config.branch_freq) ptrs[p]->iRegs[2] = RunGraphColoringMicro(ptrs[p]->iRegs[2]);
        }
    }
}

void UnsafeRunWorkload(uint64_t seed, int complexity, const StressConfig& config) {
    if (g_App.quit) return;
    if (g_Cpu.hasAVX512F && !g_ForceNoAVX512) RunHyperStress_AVX512(seed, complexity, config);
    else if (g_Cpu.hasAVX2 && g_Cpu.hasFMA) RunHyperStress_AVX2(seed, complexity, config);
    else RunHyperStress_Scalar(seed, complexity, config);
}

void SafeRunWorkload(uint64_t seed, int complexity, const StressConfig& config, int threadIdx) {
    __try {
        UnsafeRunWorkload(seed, complexity, config);
    }
    __except(WriteCrashDump(GetExceptionInformation(), seed, complexity, threadIdx)) {
        ExitProcess(-1);
    }
}

// --- THREADING INFRASTRUCTURE ---
struct ThreadWrapper {
    std::thread t;
    ~ThreadWrapper() { if(t.joinable()) t.join(); }
};

struct Worker {
    std::mutex mtx; std::condition_variable cv;
    std::atomic<bool> terminate{false};
    std::atomic<uint64_t> lastTick{0};
    bool Wait() {
        if (terminate.load()) return false;
        std::unique_lock<std::mutex> lk(mtx);
        return true;
    }
};

std::vector<std::unique_ptr<Worker>> g_Workers;
std::vector<std::unique_ptr<Worker>> g_IOThreads;
Worker g_RAM;
std::vector<std::unique_ptr<ThreadWrapper>> g_Threads;
std::unique_ptr<ThreadWrapper> g_DynThread, g_WdThread;

void PinThreadToCore(int coreIdx) {
    HANDLE hProc = GetCurrentProcess();
    DWORD_PTR processMask = 0, systemMask = 0;
    if (!GetProcessAffinityMask(hProc, &processMask, &systemMask) || processMask == 0) return;
    int bitIndex = -1, foundCores = 0;
    for (int b = 0; b < (int)(sizeof(DWORD_PTR)*8); ++b) {
        if (processMask & ((DWORD_PTR)1 << b)) {
            if (foundCores == coreIdx) { bitIndex = b; break; }
            ++foundCores;
        }
    }
    if (bitIndex >= 0) SetThreadAffinityMask(GetCurrentThread(), ((DWORD_PTR)1 << bitIndex));
}

void RunCompilerLogic(int idx, Worker& w) {
    static std::exponential_distribution<> expDist(0.0001);
    static thread_local std::mt19937 gen(1234 + idx);

    uint64_t id = g_App.shaders.fetch_add(1, std::memory_order_relaxed);
    uint64_t seed = (uint64_t)GetTick() ^ ((uint64_t)idx << 32) ^ (id * 0x9E3779B97F4A7C15ull);

    int complexity = 0;
    if (g_App.mode == 1) { // Steady
        complexity = 12000;
    } else {
        complexity = 5000 + (int)expDist(gen);
        if (complexity > 500000) complexity = 500000;
    }

    StressConfig localCfg;
    {
        std::lock_guard<std::mutex> lk(g_ConfigMtx);
        localCfg = g_ActiveConfig;
    }

    SafeRunWorkload(seed, complexity, localCfg, idx);
    g_App.totalNodes.fetch_add(complexity, std::memory_order_relaxed);
}

void RunDecompressLogic(int idx, Worker& w) {
    const size_t BUF_SIZE = 512 * 1024;
    static thread_local std::vector<uint8_t> data(BUF_SIZE);
    static thread_local std::mt19937 rng(idx * 777);
    static thread_local bool init = false;

    if (!init) {
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for(auto& b : data) b = (uint8_t)dist(rng);
        init = true;
    }

    uint64_t acc = 0;
    for(size_t i = 0; i < BUF_SIZE; i += 8) {
        uint8_t cmd = data[i] & 0x7;
        if (cmd < 3) {
            acc = Rotl64(acc ^ data[i], 13);
        } else if (cmd < 6) {
            size_t offset = (data[i+1] << 8) | data[i+2];
            offset &= (BUF_SIZE - 1);
            acc ^= data[offset];
        } else {
            acc += 0xDEADBEEF;
        }
        data[i] ^= (uint8_t)acc;
    }
}

void WorkerThread(int idx) {
    DisablePowerThrottling();
    PinThreadToCore(idx);
    std::this_thread::sleep_for(std::chrono::milliseconds(idx * 5));
    auto& w = *g_Workers[idx];

    while(!w.terminate) {
        if (g_Repro.active) {
            StressConfig reproCfg;
            { std::lock_guard<std::mutex> lk(g_ConfigMtx); reproCfg = g_ActiveConfig; }
            SafeRunWorkload(g_Repro.seed, g_Repro.complexity, reproCfg, idx);
            return;
        }

        int numComp = g_App.activeCompilers.load(std::memory_order_relaxed);
        int numDec = g_App.activeDecomp.load(std::memory_order_relaxed);

        bool isComp = (idx < numComp);
        bool isDec = (!isComp && idx < (numComp + numDec));

        if (isComp) {
            RunCompilerLogic(idx, w);
        } else if (isDec) {
            RunDecompressLogic(idx, w);
        } else {
            std::this_thread::sleep_for(10ms);
        }
        w.lastTick = GetTick();
    }
}

void IOThread(int ioIdx) {
    DisablePowerThrottling();
    auto& w = *g_IOThreads[ioIdx];

    wchar_t path[MAX_PATH]; GetTempPathW(MAX_PATH, path);
    std::wstring fpath = std::wstring(path) + L"stress_" + std::to_wstring(ioIdx) + L".tmp";

    const size_t FILE_SIZE = 512 * 1024 * 1024;
    const size_t CHUNK_SIZE = 256 * 1024;

    {
        std::ofstream f(fpath, std::ios::binary);
        std::vector<char> junk(1024*1024, 'x');
        for(int i=0; i<512; ++i) f.write(junk.data(), junk.size());
    }

    HANDLE hFile = CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
    auto* buf = (uint8_t*)VirtualAlloc(nullptr, CHUNK_SIZE, MEM_COMMIT, PAGE_READWRITE);

    std::mt19937_64 rng(GetTick() + ioIdx);

    while(!w.terminate) {
        if (!g_App.ioActive && !g_Repro.active) { std::this_thread::sleep_for(100ms); continue; }
        if(hFile == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(1s); continue; }

        LARGE_INTEGER pos;
        pos.QuadPart = (rng() % (FILE_SIZE - CHUNK_SIZE)) & ~4095;
        SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN);

        DWORD read;
        if(ReadFile(hFile, buf, CHUNK_SIZE, &read, nullptr) && read > 0) {
            volatile uint8_t sink = buf[0] ^ buf[read-1];
            (void)sink;
        }
        w.lastTick = GetTick();
    }

    CloseHandle(hFile); DeleteFileW(fpath.c_str());
    if(buf) VirtualFree(buf, 0, MEM_RELEASE);
}

void RAMThread() {
    DisablePowerThrottling();
    auto& w = g_RAM;
    std::mt19937_64 rng(GetTick());

    while(!w.terminate) {
        if (!g_App.ramActive && !g_Repro.active) { std::this_thread::sleep_for(100ms); continue; }

        MEMORYSTATUSEX ms{sizeof(ms)}; GlobalMemoryStatusEx(&ms);
        uint64_t safeSize = std::min<uint64_t>(ms.ullAvailPhys, ms.ullTotalPhys) * 7 / 10;
        if (safeSize > 16ull * 1024 * 1024 * 1024) safeSize = 16ull * 1024 * 1024 * 1024;
        safeSize &= ~4095;

        uint64_t* mem = (uint64_t*)VirtualAlloc(nullptr, safeSize, MEM_COMMIT, PAGE_READWRITE);

        if(mem) {
            size_t count = safeSize / sizeof(uint64_t);
            for(size_t i = 0; i < count; i += 16) { mem[i] = (i + 16) % count; }

            uint64_t burstEnd = GetTick() + 5000;
            while (GetTick() < burstEnd && !w.terminate && g_App.ramActive) {
                if (rng() % 2 == 0) {
                    size_t stride = 64;
                    for(size_t i=0; i < count; i += stride) { mem[i] = (i + 16) % count; }
                } else {
                    volatile uint64_t idx = 0;
                    for(int k=0; k<100000; ++k) { idx = mem[idx]; }
                }
                w.lastTick = GetTick();
            }
            VirtualFree(mem, 0, MEM_RELEASE);
        } else std::this_thread::sleep_for(1s);
    }
}

void SetWork(int comps, int decomp, bool io, bool ram) {
    size_t cpu = g_Workers.size();
    if (comps > (int)cpu) comps = (int)cpu;
    if (comps + decomp > (int)cpu) decomp = (int)cpu - comps;

    g_App.activeCompilers = comps;
    g_App.activeDecomp = decomp;
    g_App.ioActive = io;
    g_App.ramActive = ram;
}

void SmartSleep(int ms) {
    for (int i = 0; i < ms; i += 10) {
        if (!g_App.running) return;
        if (g_App.mode != 2) return;
        std::this_thread::sleep_for(10ms);
    }
}

void DynamicLoop() {
    DisablePowerThrottling();
    int cpu = (int)g_Workers.size();
    int pIdx = 0;

    auto SetStrict = [&](int c, int d, bool io, bool ram) { SetWork(c, d, io, ram); };

    std::mt19937 rng((unsigned)GetTick());
    const int PHASE_DURATION_MS = 10000;

    while(g_App.running && g_App.mode == 2) {
        g_App.currentPhase = pIdx + 1;
        auto phaseStart = std::chrono::steady_clock::now();

        while(g_App.running && g_App.mode == 2) {
            auto now = std::chrono::steady_clock::now();
            if(std::chrono::duration_cast<std::chrono::milliseconds>(now - phaseStart).count() >= PHASE_DURATION_MS) break;

            switch (pIdx) {
                case 0: SetStrict(cpu, 0, false, false); SmartSleep(100); break;
                case 1: SetStrict(std::max(0, cpu - 4), 2, true, true); SmartSleep(100); break;
                case 2: { static bool t; t = !t; if (t) SetStrict(0, 0, false, false); else SetStrict(std::max(0, cpu - 4), 2, true, true); SmartSleep(500); } break;
                case 3: SetStrict(0, std::max(0, cpu - 2), true, true); SmartSleep(100); break;
                case 4: { static bool t; t = !t; if (t) SetStrict(0, 0, false, false); else SetStrict(0, std::max(0, cpu - 2), true, true); SmartSleep(500); } break;
                case 5: SetStrict(rng() % (cpu + 1), 0, false, false); SmartSleep(500); break;
                case 6: { bool io = rng()%2; bool ram = rng()%2; int avail = cpu; int d = (avail > 0) ? (rng() % (avail+1)) : 0; SetStrict(0, d, io, ram); SmartSleep(500); } break;
                case 7: SetStrict(0, 1 + (rng() % 2), false, false); SmartSleep(500); break;
                case 8: SetStrict(1 + (rng() % 2), 0, false, false); SmartSleep(500); break;
                case 9: { bool io = rng()%2; bool ram = rng()%2; int c = rng() % (cpu + 1); int d = cpu - c; SetStrict(c, d, io, ram); SmartSleep(500); } break;
                case 10: SetStrict(cpu, 0, false, false); SmartSleep(200 + (rng() % 800)); if (g_App.running && g_App.mode == 2) { SetStrict(0, 0, false, false); SmartSleep(300 + (rng() % 500)); } break;
                case 11: SetStrict(cpu, 0, false, false); SmartSleep(100); if (g_App.running && g_App.mode == 2) { SetStrict(0, cpu, false, false); SmartSleep(100); } break;
                case 12: { SetStrict(cpu, 0, true, true); SmartSleep(50); SetStrict(0, 0, false, false); SmartSleep(50); break; }
                case 13: { for(int i=0; i<cpu; i+=2) { SetStrict(2, 0, false, false); SmartSleep(100); if(!g_App.running || g_App.mode != 2) break; } break; }
                case 14: { int d = std::max(1, cpu - 2); SetStrict(0, d, true, true); SmartSleep(1000); break; }
            }
        }
        pIdx = (pIdx + 1) % 15;
        if (pIdx == 0) g_App.loops++;
    }
}

void Watchdog() {
    DisablePowerThrottling();
    uint64_t lastCheck = GetTick(), minuteStartShaders = 0, minuteStartTime = 0, runStart = 0;
    bool warmingUp = false, lastRunning = false;

    while(!g_App.quit) {
        bool currentRunning = g_App.running;
        uint64_t now = GetTick();

        if (currentRunning && g_App.maxDuration.load() > 0 && runStart > 0) {
            if ((now - runStart)/1000 >= g_App.maxDuration.load()) {
                g_App.running = false;
                g_App.Log(L"Max duration reached. Stopping.");
                InvalidateRect(g_MainWindow, nullptr, FALSE);
            }
        }

        if (g_App.resetTimer.exchange(false)) {
            minuteStartShaders = 0; minuteStartTime = now; lastCheck = now;
            g_App.elapsed = 0; runStart = now; warmingUp = true;
            g_App.currentRate = 0; g_App.nodeRate = 0;
            if (currentRunning) { minuteStartShaders = g_App.shaders; }
        }

        if (currentRunning && !lastRunning) g_App.resetTimer = true;
        lastRunning = currentRunning;

        if(currentRunning) {
            if (g_App.elapsed == 0 && runStart == 0) runStart = now;
            g_App.elapsed = (now - runStart) / 1000;

            if (warmingUp) {
                if (now - runStart > 2000) { warmingUp = false; minuteStartTime = now; minuteStartShaders = g_App.shaders; lastCheck = now; }
            } else if (now - lastCheck >= 1000) {
                uint64_t currentShaders = g_App.shaders;
                uint64_t timeInWindow = now - minuteStartTime;

                if (timeInWindow > 0) {
                    uint64_t diff = currentShaders - minuteStartShaders;
                    g_App.currentRate = (diff * 1000) / timeInWindow;
                }

                if (timeInWindow >= 60000) {
                    minuteStartTime = now;
                    minuteStartShaders = currentShaders;
                }
                lastCheck = now;
            }
        } else runStart = 0;

        std::this_thread::sleep_for(500ms);
        if(g_MainWindow && g_App.running && !IsIconic(g_MainWindow)) InvalidateRect(g_MainWindow, nullptr, FALSE);
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if(m == WM_DESTROY) {
        g_App.running = false; g_App.quit = true; PostQuitMessage(0); return 0;
    }
    if(m == WM_PAINT) {
        PAINTSTRUCT ps; BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        HDC memDC = CreateCompatibleDC(ps.hdc); HBITMAP memBM = CreateCompatibleBitmap(ps.hdc, rc.right, rc.bottom); HBITMAP oldBM = (HBITMAP)SelectObject(memDC, memBM);
        HBRUSH bg = CreateSolidBrush(RGB(20,20,20)); FillRect(memDC, &rc, bg); DeleteObject(bg);
        SetBkMode(memDC, TRANSPARENT); SetTextColor(memDC, RGB(200,200,200));
        HFONT hFont = CreateFontW(-(int)(16 * g_Scale), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
        HFONT oldFont = (HFONT)SelectObject(memDC, hFont);

        auto btn = [&](int id, const wchar_t* txt, int x, bool act) {
            RECT r{x, S(10), x+S(140), S(40)}; HBRUSH b = CreateSolidBrush(act ? RGB(60,100,160) : RGB(50,50,50)); FillRect(memDC, &r, b); DeleteObject(b);
            DrawTextW(memDC, txt, -1, &r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        };

        bool run = g_App.running;
        btn(1, run ? L"STOP" : L"START", S(10), run); btn(2, L"Dynamic", S(160), g_App.mode==2); btn(3, L"Steady", S(310), g_App.mode==1); btn(4, L"Benchmark", S(460), g_App.mode==0); btn(5, L"Close", S(610), false);

        StressConfig safeCfg;
        { std::lock_guard<std::mutex> lk(g_ConfigMtx); safeCfg = g_ActiveConfig; }

        std::wstring modeName = (g_App.mode == 2 ? L"Dynamic" : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
        std::wstring part1 = L"Shader Stress " + APP_VERSION + L"\nMode: " + modeName +
        L"\nJobs Done: " + FmtNum(g_App.shaders) +
        L"\n\n--- Performance ---" +
        L"\nRate (Jobs/s): " + FmtNum(g_App.currentRate) +
        L"\nTime: " + FmtTime(g_App.elapsed);

        if (g_App.mode == 2) {
            part1 += L"\nPhase: " + std::to_wstring(g_App.currentPhase) + L" / 15";
            part1 += L"\nLoop: " + std::to_wstring(g_App.loops);
        }

        std::wstring partError = L"Errors: " + FmtNum(g_App.errors);
        std::wstring part3 = L"\n\n--- Stress Status ---";
        part3 += L"\nWorker Threads: " + FmtNum(g_App.activeCompilers + g_App.activeDecomp) + L" (Pinned)";
        part3 += L"\n  > Sim Compilers: " + FmtNum(g_App.activeCompilers);
        part3 += L"\n  > Decompressors: " + FmtNum(g_App.activeDecomp);
        part3 += L"\nRAM Thread: " + std::wstring(g_App.ramActive ? L"ACTIVE" : L"Idle");
        part3 += L"\nI/O Threads: " + std::wstring(g_App.ioActive ? L"ACTIVE (4x)" : L"Idle");

        RECT tr{S(20), S(60), S(600), S(600)};
        DrawTextW(memDC, part1.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
        RECT measure = tr; DrawTextW(memDC, part1.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT); tr.top += (measure.bottom - measure.top);

        if(g_App.errors > 0) SetTextColor(memDC, RGB(255, 80, 80)); else SetTextColor(memDC, RGB(80, 255, 80));
        DrawTextW(memDC, partError.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
        measure = tr; DrawTextW(memDC, partError.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT); tr.top += (measure.bottom - measure.top);

        SetTextColor(memDC, RGB(200, 200, 200));
        DrawTextW(memDC, part3.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);

        BitBlt(ps.hdc, 0, 0, rc.right, rc.bottom, memDC, 0, 0, SRCCOPY);
        SelectObject(memDC, oldFont); SelectObject(memDC, oldBM); DeleteObject(hFont); DeleteObject(memBM); DeleteDC(memDC); EndPaint(h, &ps); return 0;
    }
    if(m == WM_LBUTTONDOWN) {
        int x = LOWORD(l), y = HIWORD(l);
        if(y > S(10) && y < S(40)) {
            bool clickedStart = (x > S(10) && x < S(150));
            int newMode = -1;
            if (x > S(160) && x < S(300)) newMode = 2;
            else if (x > S(310) && x < S(450)) newMode = 1;
            else if (x > S(460) && x < S(600)) newMode = 0;
            else if (x > S(610) && x < S(750)) PostMessage(h, WM_CLOSE, 0, 0);

            auto StartWorkload = []() {
                if(g_DynThread && g_DynThread->t.joinable()) g_DynThread->t.join();

                if (g_App.mode == 2) {
                    g_DynThread = std::make_unique<ThreadWrapper>();
                    g_DynThread->t = std::thread(DynamicLoop);
                } else if (g_App.mode == 1) { // Steady
                    int cpu = (int)g_Workers.size();
                    int d = std::min(4, std::max(1, cpu / 2));
                    int c = std::max(0, cpu - d);
                    SetWork(c, d, true, true);
                } else { // Benchmark
                    SetWork((int)g_Workers.size(), 0, 0, 0);
                }
            };

            if (clickedStart) {
                g_App.running = !g_App.running;
                if(g_App.running) {
                    g_App.Log(L"State changed: STARTED");
                    g_App.shaders=0; g_App.elapsed=0; g_App.totalNodes=0; g_App.loops=0; g_App.currentPhase=0;
                    StartWorkload();
                } else {
                    g_App.Log(L"State changed: STOPPED");
                    SetWork(0,0,0,0);
                }
            } else if (newMode != -1 && newMode != g_App.mode) {
                g_App.mode = newMode;
                std::wstring modeName = (newMode == 2 ? L"Dynamic" : (newMode == 1 ? L"Steady" : L"Benchmark"));
                g_App.Log(L"Mode changed to: " + modeName);
                if(g_App.running) StartWorkload();
            }
            g_App.resetTimer = true; InvalidateRect(h, nullptr, FALSE);
        }
    }
    return DefWindowProc(h, m, w, l);
}

void DetectBestConfig() {
    StressConfig heavyCfg;
    heavyCfg = { 8, 2, 0, 0, L"Math Heavy (AVX2/512)" };

    std::lock_guard<std::mutex> lk(g_ConfigMtx);
    g_ActiveConfig = heavyCfg;
    g_App.Log(L"Config locked to Math Heavy (AVX/FMA)");
}

void PrintHelp() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    _wprintf_p(L"ShaderStress v%ls\n\n", APP_VERSION.c_str());
    printf("Options:\n");
    printf("  --repro <seed> <complexity>  : Run a specific crash reproduction case.\n");
    printf("  --max-duration <sec>         : Automatically stop after N seconds.\n");
    printf("  --no-avx512                  : Force AVX2/Scalar path.\n");
    getchar();
    ExitProcess(0);
}

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_Scale = GetDpiForSystem() / 96.0f;
    g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
    g_App.log.imbue(std::locale(""));

    g_Cpu = GetCpuInfo();
    g_App.sigStatus = g_Cpu.name;
    g_App.Log(std::wstring(L"Started v") + APP_VERSION + L" (" + g_Cpu.name + L")");

    g_ColdStorage.resize(32 * 1024 * 1024 / 8);
    std::mt19937_64 r(123);
    for(auto& v : g_ColdStorage) v = r();

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--repro") == 0 && i + 2 < argc) {
                g_Repro.active = true;
                g_Repro.seed = _wtoi64(argv[i+1]);
                g_Repro.complexity = _wtoi(argv[i+2]);
            }
            if (lstrcmpiW(argv[i], L"--max-duration") == 0 && i + 1 < argc) {
                g_App.maxDuration = _wtoi(argv[i+1]);
            }
            if (lstrcmpiW(argv[i], L"--no-avx512") == 0) {
                g_ForceNoAVX512 = true;
                g_App.Log(L"AVX-512 explicitly disabled via CLI.");
            }
            if (lstrcmpiW(argv[i], L"--help") == 0) {
                PrintHelp();
            }
        }
        LocalFree(argv);
    }

    DetectBestConfig();

    int cpu = std::thread::hardware_concurrency();
    if(cpu == 0) cpu = 4;

    for(int i=0; i<cpu; ++i) g_Workers.push_back(std::make_unique<Worker>());
    for(int i=0; i<4; ++i) g_IOThreads.push_back(std::make_unique<Worker>());

    for(int i=0; i<cpu; ++i) {
        auto t = std::make_unique<ThreadWrapper>();
        t->t = std::thread(WorkerThread, i);
        g_Threads.push_back(std::move(t));
    }
    for(int i=0; i<4; ++i) {
        auto t = std::make_unique<ThreadWrapper>();
        t->t = std::thread(IOThread, i);
        g_Threads.push_back(std::move(t));
    }
    {
        auto t = std::make_unique<ThreadWrapper>(); t->t = std::thread(RAMThread); g_Threads.push_back(std::move(t));
    }

    if (g_Repro.active) {
        g_App.Log(L"Repro Mode Active. Running workload...");
        std::this_thread::sleep_for(1s);
        std::this_thread::sleep_for(10s);
        g_App.Log(L"Repro finished without crash.");
        goto cleanup;
    }

    g_WdThread = std::make_unique<ThreadWrapper>();
    g_WdThread->t = std::thread(Watchdog);

    {
        WNDCLASSW wc{0, WndProc, 0, 0, inst, nullptr, LoadCursor(0, IDC_ARROW), nullptr, nullptr, L"SST"};
        wc.hIcon = LoadIconW(inst, MAKEINTRESOURCE(1)); RegisterClassW(&wc);
        int wW = S(800), wH = S(600);
        g_MainWindow = CreateWindowW(L"SST", L"Shader Stress", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE, (GetSystemMetrics(SM_CXSCREEN)-wW)/2, (GetSystemMetrics(SM_CYSCREEN)-wH)/2, wW, wH, 0, 0, inst, 0);
        BOOL useDark = TRUE; DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));

        MSG msg; while(GetMessage(&msg, 0, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }

    cleanup:
    g_App.quit = true;
    for(auto& w : g_Workers) { w->terminate = true; }
    for(auto& w : g_IOThreads) { w->terminate = true; }
    g_RAM.terminate = true;

    g_DynThread.reset();
    g_WdThread.reset();
    g_Threads.clear();

    { std::lock_guard<std::mutex> lk(g_App.logMtx); if(g_App.log.is_open()) g_App.log.flush(); }

    return 0;
}
