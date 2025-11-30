#define _WIN32_WINNT 0x0A00
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <processthreadsapi.h>
#include <shellapi.h>
#include <cstdio>
#include <intrin.h>

// --- ARCHITECTURE COMPATIBILITY HEADER ---
// This block ensures the code compiles on both x86 (Intel/AMD) and ARM64 (Snapdragon/Apple).

#if defined(_M_AMD64) || defined(_M_IX86)
// x86/x64 Architecture
#include <immintrin.h> // AVX/AVX2/AVX512 Intrinsics
#elif defined(_M_ARM64)
// ARM64 Architecture
// Map x86 Bit Manipulation intrinsics to ARM64 hardware instructions
// _lzcnt_u64 (Leading Zeros) -> _CountLeadingZeros64 (uses 'clz' instruction)
// _tzcnt_u64 (Trailing Zeros) -> _CountTrailingZeros64 (uses 'rbit' + 'clz')
#define _lzcnt_u64 _CountLeadingZeros64
#define _tzcnt_u64 _CountTrailingZeros64
#endif

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
#include <memory>

#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "dwmapi")
#pragma comment(lib, "shcore")
#pragma comment(lib, "shell32")
#pragma comment(lib, "dbghelp")

namespace fs = std::filesystem;
using namespace std::chrono_literals;

const std::wstring APP_VERSION = L"2.1-Universal";

// --- Constants & Configuration ---
constexpr uint64_t GOLDEN_RATIO = 0x9E3779B97F4A7C15ull;
constexpr size_t IO_CHUNK_SIZE = 256 * 1024;
constexpr size_t IO_FILE_SIZE = 512 * 1024 * 1024;
constexpr int BENCHMARK_DURATION_SEC = 180;

// --- RAII Wrappers ---
struct ScopedHandle {
    HANDLE h;
    ScopedHandle(HANDLE _h) : h(_h) {}
    ~ScopedHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
};

struct ScopedMem {
    void* ptr;
    ScopedMem(size_t size) {
        if (size > 0) ptr = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
        else ptr = nullptr;
    }
    ~ScopedMem() { if (ptr) VirtualFree(ptr, 0, MEM_RELEASE); }
    template<typename T> T* As() { return static_cast<T*>(ptr); }
};

// --- Helpers & Global State ---
static inline uint64_t Rotl64(uint64_t v, unsigned r) { return (v << r) | (v >> (64u - r)); }
static inline uint64_t GetTick() { return GetTickCount64(); }

std::wstring FmtNum(uint64_t v) {
    if (v < 1000) return std::to_wstring(v);
    wchar_t buf[64];
    double n = (double)v;
    const wchar_t* suffix = L"";
    if (v >= 1000000) { n /= 1000000.0; suffix = L"M"; }
    else { n /= 1000.0; suffix = L"k"; }
    _snwprintf_s(buf, _TRUNCATE, L"%.1f%s", n, suffix);
    std::wstring res(buf);
    std::replace(res.begin(), res.end(), L',', L'.');
    return res;
}

std::wstring FmtTime(uint64_t s) {
    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(2) << (s/3600) << L":"
    << std::setw(2) << ((s%3600)/60) << L":"
    << std::setw(2) << (s%60);
    return ss.str();
}

struct CpuFeatures {
    bool hasAVX2 = false;
    bool hasAVX512F = false;
    bool hasFMA = false;
    std::wstring name;
    std::wstring brand;
};

// Helper to get CPU Brand String
std::wstring GetCpuBrand() {
    #if defined(_M_ARM64)
    return L"ARM64 Processor";
    #else
    // x86 CPUID query
    int regs[4];
    char brand[0x40] = { 0 };
    __cpuid(regs, 0x80000000);
    if (regs[0] >= 0x80000004) {
        __cpuid((int*)brand, 0x80000002);
        __cpuid((int*)brand + 4, 0x80000003);
        __cpuid((int*)brand + 8, 0x80000004);
    }
    std::string s(brand);
    s.erase(std::unique(s.begin(), s.end(), [](char a, char b){ return a == ' ' && b == ' '; }), s.end());
    if (!s.empty() && s[0] == ' ') s.erase(0, 1);
    if (s.empty()) return L"Unknown CPU";
    return std::wstring(s.begin(), s.end());
    #endif
}

CpuFeatures GetCpuInfo() {
    CpuFeatures f;
    f.brand = GetCpuBrand();

    #if defined(_M_ARM64)
    // ARM64 always supports NEON (FMA equivalent), but lacks AVX
    f.hasFMA = true;
    f.hasAVX2 = false;
    f.hasAVX512F = false;
    f.name = L"ARM64";
    #else
    // Standard x86 detection
    int regs[4];
    __cpuid(regs, 0);
    int nIds = regs[0];

    if (nIds >= 1) {
        __cpuid(regs, 1);
        f.hasFMA = (regs[2] & (1 << 12)) != 0;
        bool osExample = (regs[2] & (1 << 27)) != 0;
        bool cpuAVX = (regs[2] & (1 << 28)) != 0;

        if (osExample && cpuAVX) {
            unsigned long long xcr0 = _xgetbv(0);
            if ((xcr0 & 0x6) == 0x6) {
                if (nIds >= 7) {
                    __cpuidex(regs, 7, 0);
                    f.hasAVX2 = (regs[1] & (1 << 5)) != 0;
                    f.hasAVX512F = (regs[1] & (1 << 16)) != 0;
                    if (f.hasAVX512F && (xcr0 & 0xE0) != 0xE0) f.hasAVX512F = false;
                }
            }
        }
    }

    if (f.hasAVX512F) f.name = L"AVX-512";
    else if (f.hasAVX2 && f.hasFMA) f.name = L"AVX2";
    else f.name = L"Scalar";
    #endif
    return f;
}

CpuFeatures g_Cpu;
bool g_ForceNoAVX512 = false;
bool g_ForceNoAVX2 = false;

struct ReproSettings {
    bool active = false;
    uint64_t seed = 0;
    int complexity = 0;
} g_Repro;

struct StressConfig {
    int fma_intensity = 1;
    int int_intensity = 1;
    int mem_pressure = 0;
    int branch_freq = 0;
    std::wstring name = L"Default";
};

StressConfig g_ActiveConfig;
std::mutex g_ConfigMtx;
std::atomic<uint64_t> g_ConfigVersion{0};
std::vector<uint64_t> g_ColdStorage;
std::mutex g_StateMtx;

enum { WL_AUTO = 0, WL_AVX512 = 1, WL_AVX2 = 2, WL_SCALAR_MATH = 3, WL_SCALAR_SIM = 4 };

struct AppState {
    std::atomic<bool> running{false}, quit{false};
    std::atomic<int> mode{2}, activeCompilers{0}, activeDecomp{0}, loops{0};
    std::atomic<bool> ioActive{false}, ramActive{false};
    std::atomic<bool> resetTimer{false};
    std::atomic<int> currentPhase{0};
    std::atomic<int> selectedWorkload{WL_AUTO};

    std::atomic<uint64_t> shaders{0};
    std::atomic<uint64_t> totalNodes{0};
    std::atomic<uint64_t> errors{0}, elapsed{0};
    std::atomic<uint64_t> currentRate{0};

    std::atomic<uint64_t> benchRates[3];
    std::atomic<int> benchWinner{-1};
    std::atomic<bool> benchComplete{false};

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
        if(g_Repro.active) std::wcout << msg << std::endl;
    }

    void LogRaw(const std::wstring& msg) {
        std::lock_guard<std::mutex> lk(logMtx);
        if(log.is_open()) {
            log << msg << std::endl;
        }
    }
} g_App;

HWND g_MainWindow = nullptr;
float g_Scale = 1.0f;
int S(int v) { return (int)(v * g_Scale); }

void DisablePowerThrottling() {
    PROCESS_POWER_THROTTLING_STATE PowerThrottling = {0};
    PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    PowerThrottling.StateMask = 0;
    SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &PowerThrottling, sizeof(PowerThrottling));
}

void PinThreadToCore(int coreIdx) {
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

LONG WINAPI WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo, uint64_t seed, int complexity, int threadIdx) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf; localtime_s(&tm_buf, &time);

    std::stringstream ss; ss << std::put_time(&tm_buf, "%Y-%m-%d_%H-%M-%S");
    std::string folderName = "Crash_" + ss.str() + "_Thread" + std::to_string(threadIdx);
    fs::create_directories(folderName);
    fs::path basePath = fs::path(folderName);

    g_App.Log(L"CRASH DETECTED in Thread " + std::to_wstring(threadIdx) + L" | Seed: " + FmtNum(seed));

    std::wstring dumpPath = (basePath / "crash.dmp").wstring();
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pExceptionInfo;
        mdei.ClientPointers = FALSE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                          (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules),
                          &mdei, nullptr, nullptr);
        CloseHandle(hFile);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

struct alignas(64) HotNode { float fRegs[16]; uint64_t iRegs[8]; };
__forceinline uint64_t RunGraphColoringMicro(uint64_t val) { uint64_t x = val; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x * 0x2545F4914F6CDD1Dull; }
__forceinline void InterlockedXorCold(uint64_t* ptr, uint64_t val) { _InterlockedXor64((volatile __int64*)ptr, (long long)val); }

struct FakeAstNode { uint32_t children[4]; uint32_t meta; uint64_t payload; };

#if !defined(_M_ARM64)
// --- X86 SPECIFIC KERNELS (AVX2/AVX512) ---
// These are only compiled when targeting x64/x86
void RunHyperStress_AVX2(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) {
        uint64_t s = seed + i * GOLDEN_RATIO;
        for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f;
        for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32);
    }

    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
    uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    __m256 vFMA = _mm256_set1_ps(1.0001f);
    __m256 vMul = _mm256_set1_ps(0.9999f);

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode* n[4] = { &nodes[i%BLOCK_SIZE], &nodes[(i+1)%BLOCK_SIZE], &nodes[(i+2)%BLOCK_SIZE], &nodes[(i+3)%BLOCK_SIZE] };
        for(int k=0; k < config.int_intensity; ++k) {
            for(int j=0; j<4; ++j) n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
        }
        for(int k=0; k < config.fma_intensity; ++k) {
            for(int j=0; j<4; ++j) {
                __m256 fA = _mm256_load_ps(n[j]->fRegs);
                __m256 fB = _mm256_load_ps(n[j]->fRegs+8);
                fA = _mm256_fmadd_ps(fA, vMul, vFMA);
                fB = _mm256_fmadd_ps(fB, vMul, vFMA);
                _mm256_store_ps(n[j]->fRegs, fA);
                _mm256_store_ps(n[j]->fRegs+8, fB);
            }
        }
        if (config.mem_pressure > 0 && coldPtr) {
            for (int m = 0; m < config.mem_pressure; ++m) {
                for(int j=0; j<4; ++j) InterlockedXorCold(&coldPtr[n[j]->iRegs[0]&coldMask], n[j]->iRegs[1]);
            }
        }
    }
}

void RunHyperStress_AVX512(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) {
        uint64_t s = seed + i * GOLDEN_RATIO;
        for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f;
        for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32);
    }
    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
    uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    __m512 vFMA = _mm512_set1_ps(1.0001f);
    __m512 vMul = _mm512_set1_ps(0.9999f);

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode* n[4] = { &nodes[i%BLOCK_SIZE], &nodes[(i+1)%BLOCK_SIZE], &nodes[(i+2)%BLOCK_SIZE], &nodes[(i+3)%BLOCK_SIZE] };
        for(int k=0; k < config.int_intensity; ++k) {
            for(int j=0; j<4; ++j) n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
        }
        for(int k=0; k < config.fma_intensity; ++k) {
            for(int j=0; j<4; ++j) {
                __m512 f = _mm512_load_ps(n[j]->fRegs);
                f = _mm512_fmadd_ps(f, vMul, vFMA);
                _mm512_store_ps(n[j]->fRegs, f);
            }
        }
        if (config.mem_pressure > 0 && coldPtr) {
            for (int m = 0; m < config.mem_pressure; ++m) {
                for(int j=0; j<4; ++j) InterlockedXorCold(&coldPtr[n[j]->iRegs[0]&coldMask], n[j]->iRegs[1]);
            }
        }
    }
}
#endif // !defined(_M_ARM64)

// --- SCALAR KERNELS (Universal) ---

void RunHyperStress_Scalar(uint64_t seed, int complexity, const StressConfig& config) {
    const int BLOCK_SIZE = 512; alignas(64) HotNode nodes[BLOCK_SIZE];
    for(int i=0; i<BLOCK_SIZE; ++i) {
        uint64_t s = seed + i * GOLDEN_RATIO;
        for(int j=0; j<16; ++j) nodes[i].fRegs[j] = (float)((s>>(j*4))&0xFF)*1.1f;
        for(int j=0; j<8; ++j) nodes[i].iRegs[j] = s^((uint64_t)j<<32);
    }
    size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
    uint64_t* coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
    float vFMA = 1.0001f;
    float vMul = 0.9999f;

    for (int i = 0; i < complexity; i += 4) {
        if (g_App.quit) break;
        HotNode* n[4] = { &nodes[i%BLOCK_SIZE], &nodes[(i+1)%BLOCK_SIZE], &nodes[(i+2)%BLOCK_SIZE], &nodes[(i+3)%BLOCK_SIZE] };
        for(int k=0; k < config.int_intensity; ++k) {
            for(int j=0; j<4; ++j) n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
        }
        for(int k=0; k < config.fma_intensity; ++k) {
            for(int j=0; j<4; ++j) {
                // Scalar Unroll - Compiles to VFMADD (x86) or FMLA (ARM64)
                for(int f=0; f<16; ++f) {
                    n[j]->fRegs[f] = (n[j]->fRegs[f] * vMul) + vFMA;
                }
            }
        }
        if (config.mem_pressure > 0 && coldPtr) {
            for (int m = 0; m < config.mem_pressure; ++m) {
                for(int j=0; j<4; ++j) InterlockedXorCold(&coldPtr[n[j]->iRegs[0]&coldMask], n[j]->iRegs[1]);
            }
        }
    }
}

#define CASE_BLOCK_32(start, code) \
case start: case start+1: case start+2: case start+3: \
case start+4: case start+5: case start+6: case start+7: \
case start+8: case start+9: case start+10: case start+11: \
case start+12: case start+13: case start+14: case start+15: \
case start+16: case start+17: case start+18: case start+19: \
case start+20: case start+21: case start+22: case start+23: \
case start+24: case start+25: case start+26: case start+27: \
case start+28: case start+29: case start+30: case start+31: \
{ code; } break;

#define CASE_BLOCK_16(start, code) \
case start: case start+1: case start+2: case start+3: \
case start+4: case start+5: case start+6: case start+7: \
case start+8: case start+9: case start+10: case start+11: \
case start+12: case start+13: case start+14: case start+15: \
{ code; } break;

void RunRealisticCompilerSim_V3(uint64_t seed, int complexity, const StressConfig& config) {
    constexpr size_t TREE_NODES = 16384;
    constexpr size_t HASH_BUCKETS = 4096;
    constexpr size_t STRING_POOL_SIZE = 64 * 1024;
    constexpr size_t BITVEC_WORDS = 256;

    auto tree = std::make_unique<FakeAstNode[]>(TREE_NODES);
    auto hashTable = std::make_unique<uint64_t[]>(HASH_BUCKETS);
    struct HashEntry {
        uint64_t key;
        uint32_t strOffset;
        uint32_t strLen;
        uint32_t next;
        uint32_t nodeRef;
    };
    auto tableEntries = std::make_unique<HashEntry[]>(HASH_BUCKETS);
    auto stringPool = std::make_unique<char[]>(STRING_POOL_SIZE);

    auto liveInArr = std::make_unique<uint64_t[]>(BITVEC_WORDS);
    auto liveOutArr = std::make_unique<uint64_t[]>(BITVEC_WORDS);
    auto liveKillArr = std::make_unique<uint64_t[]>(BITVEC_WORDS);

    uint64_t* liveIn = liveInArr.get();
    uint64_t* liveOut = liveOutArr.get();
    uint64_t* liveKill = liveKillArr.get();

    for (size_t i = 0; i < STRING_POOL_SIZE; ++i) {
        stringPool[i] = (char)((seed + i * 13) % 255);
    }
    for (size_t i = 0; i < TREE_NODES; ++i) {
        uint64_t s = seed + i * GOLDEN_RATIO;
        tree[i].payload = s;
        tree[i].meta = (uint32_t)s;
        for (int k = 0; k < 4; ++k)
            tree[i].children[k] = (uint32_t)((s >> (k * 5)) & (TREE_NODES - 1));
    }
    for (size_t i = 0; i < HASH_BUCKETS; ++i) {
        uint64_t s = seed ^ (i * 0x517cc1b727220a95ULL);
        tableEntries[i].key = s;
        tableEntries[i].strOffset = (uint32_t)(s & (STRING_POOL_SIZE - 256));
        tableEntries[i].strLen = 4 + ((uint32_t)s & 0x1F);
        tableEntries[i].next = 0;
        tableEntries[i].nodeRef = (uint32_t)(s & (TREE_NODES - 1));
    }
    for (size_t i = 0; i < BITVEC_WORDS; ++i) {
        liveIn[i] = seed ^ Rotl64(seed, (unsigned)i);
        liveOut[i] = ~liveIn[i];
        liveKill[i] = liveIn[i] ^ 0xAAAAAAAA55555555;
    }

    uint64_t acc0 = seed, acc1 = seed + 1, acc2 = seed + 2, acc3 = seed + 3;

    for (int iter = 0; iter < complexity; iter += 4) {
        if (g_App.quit) break;
        // Phase 1: Symbol Lookup
        {
            uint32_t strStart = (uint32_t)(acc0 & (STRING_POOL_SIZE - 256));
            uint32_t strLen = 4 + (uint32_t)(acc1 & 0x1F);

            uint64_t hash = 0xcbf29ce484222325ULL;
            for (uint32_t i = 0; i < strLen; ++i) {
                hash ^= (unsigned char)stringPool[strStart + i];
                hash *= 0x100000001b3ULL;
            }

            uint32_t bucket = (uint32_t)(hash & (HASH_BUCKETS - 1));
            uint32_t probes = 0;
            while (tableEntries[bucket].key != 0 && probes < 8) {
                if (tableEntries[bucket].strLen == strLen) {
                    bool match = true;
                    for (uint32_t i = 0; i < strLen; ++i) {
                        if (stringPool[tableEntries[bucket].strOffset + i] != stringPool[strStart + i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) { acc0 ^= tableEntries[bucket].nodeRef; break; }
                }
                bucket = (bucket + 1) & (HASH_BUCKETS - 1);
                probes++;
            }
        }
        // Phase 2: Pointer Chasing (DOM Tree)
        {
            uint32_t nodeIdx = (uint32_t)(acc0 & (TREE_NODES - 1));
            for (int depth = 0; depth < 12; ++depth) {
                FakeAstNode& node = tree[nodeIdx];
                uint32_t idom = node.children[0];
                acc1 = Rotl64(acc1 ^ tree[idom].payload, 7);
                uint32_t selector = (uint32_t)((acc1 >> (depth * 2)) & 0x3);
                nodeIdx = node.children[selector];
                if (node.meta & 0x100) {
                    acc2 ^= tree[node.children[1]].payload;
                    acc2 ^= tree[node.children[2]].payload;
                }
            }
        }
        // Phase 3: Register Pressure & ALU
        {
            uint64_t vr[16];
            for (int i = 0; i < 16; ++i) vr[i] = acc0 + i * GOLDEN_RATIO;

            for (int op = 0; op < 32; ++op) {
                int dst = (acc1 >> (op & 7)) & 0xF;
                int src1 = (acc2 >> ((op + 1) & 7)) & 0xF;
                int src2 = (acc3 >> ((op + 2) & 7)) & 0xF;

                uint32_t opcode = (uint32_t)((vr[src1] ^ vr[src2]) & 0xFF);
                switch (opcode) {
                    CASE_BLOCK_32(0,   vr[dst] = vr[src1] + vr[src2]; )
                    CASE_BLOCK_32(32,  vr[dst] = vr[src1] - vr[src2]; )
                    CASE_BLOCK_32(64,  vr[dst] = vr[src1] * vr[src2]; )
                    CASE_BLOCK_16(96,  vr[dst] = vr[src1] ^ vr[src2]; )
                    CASE_BLOCK_16(112, vr[dst] = Rotl64(vr[src1], src2 & 63); )
                    // Bit intrinsics handled by top-of-file macros on ARM64
                    CASE_BLOCK_16(128, vr[dst] = __popcnt64(vr[src1]); )
                    CASE_BLOCK_16(144, vr[dst] = _lzcnt_u64(vr[src1]); )
                    CASE_BLOCK_16(160, vr[dst] = _tzcnt_u64(vr[src1]); )
                    CASE_BLOCK_16(176, vr[dst] = vr[src2] ? vr[src1] / vr[src2] : vr[src1]; )
                    CASE_BLOCK_32(192, vr[dst] = tree[vr[src1] & (TREE_NODES-1)].payload; )
                    default:
                        vr[dst] = (vr[src1] << (src2 & 31)) | (vr[src1] >> (32 - (src2 & 31)));
                        break;
                }
            }
            acc0 = vr[0] ^ vr[15];
        }
        // Phase 4: BitVectors
        {
            for (size_t w = 0; w < BITVEC_WORDS; ++w) {
                uint64_t gen = tree[w & (TREE_NODES-1)].payload;
                uint64_t kill = liveKill[w];
                liveOut[w] = gen | (liveIn[w] & ~kill);
                liveIn[w] = liveOut[(w + 1) & (BITVEC_WORDS - 1)] | liveOut[(w + 7) & (BITVEC_WORDS - 1)];
            }
            for (size_t w = 0; w < BITVEC_WORDS; w += 4) {
                acc3 += __popcnt64(liveIn[w]) + __popcnt64(liveIn[w+1])
                + __popcnt64(liveIn[w+2]) + __popcnt64(liveIn[w+3]);
            }
        }
    }

    volatile uint64_t sink = acc0 ^ acc1 ^ acc2 ^ acc3;
    (void)sink;
}

void UnsafeRunWorkload(uint64_t seed, int complexity, const StressConfig& config) {
    if (g_App.quit) return;

    int sel = g_App.selectedWorkload.load();
    #if defined(_M_ARM64)
    bool can512 = false;
    bool canAVX2 = false;
    #else
    bool can512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
    bool canAVX2 = g_Cpu.hasAVX2 && g_Cpu.hasFMA && !g_ForceNoAVX2;
    #endif

    #if !defined(_M_ARM64)
    if (sel == WL_AVX512 && can512) { RunHyperStress_AVX512(seed, complexity, config); return; }
    if (sel == WL_AVX2 && canAVX2) { RunHyperStress_AVX2(seed, complexity, config); return; }
    #endif

    if (sel == WL_SCALAR_MATH) { RunHyperStress_Scalar(seed, complexity, config); return; }
    if (sel == WL_SCALAR_SIM) { RunRealisticCompilerSim_V3(seed, complexity, config); return; }

    #if !defined(_M_ARM64)
    if (can512) RunHyperStress_AVX512(seed, complexity, config);
    else if (canAVX2) RunHyperStress_AVX2(seed, complexity, config);
    else
        #endif
        RunRealisticCompilerSim_V3(seed, complexity, config);
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
    alignas(64) std::atomic<bool> terminate{false};
    alignas(64) std::atomic<uint64_t> localShaders{0};
    std::atomic<uint64_t> lastTick{0};
    uint8_t pad[64];
};

std::vector<std::unique_ptr<Worker>> g_Workers;
std::vector<std::unique_ptr<Worker>> g_IOThreads;
Worker g_RAM;
std::vector<std::unique_ptr<ThreadWrapper>> g_Threads;
std::unique_ptr<ThreadWrapper> g_DynThread, g_WdThread;

void RunCompilerLogic(int idx, Worker& w) {
    static thread_local std::array<int, 1024> pregenComplexity;
    static thread_local size_t complexityIdx = 0;
    static thread_local bool initialized = false;

    if (!initialized) {
        std::mt19937 gen(1234 + idx);
        std::exponential_distribution<> dist(0.0001);
        for (auto& c : pregenComplexity) {
            double dComp = std::min(dist(gen), 495000.0);
            c = 5000 + static_cast<int>(dComp);
        }
        initialized = true;
    }

    int complexity = pregenComplexity[complexityIdx++ & 1023];
    if (g_App.mode == 1) complexity = 12000;
    static thread_local uint64_t lastVer = 0;
    static thread_local StressConfig cachedCfg;
    if (lastVer != g_ConfigVersion.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lk(g_ConfigMtx);
        cachedCfg = g_ActiveConfig;
        lastVer = g_ConfigVersion;
    }

    uint64_t seed = (uint64_t)GetTick() ^ ((uint64_t)idx << 32) ^ (w.localShaders.load(std::memory_order_relaxed) * GOLDEN_RATIO);
    SafeRunWorkload(seed, complexity, cachedCfg, idx);
    w.localShaders.fetch_add(1, std::memory_order_relaxed);
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
        if (cmd < 3) acc = Rotl64(acc ^ data[i], 13);
        else if (cmd < 6) {
            size_t offset = (data[i+1] << 8) | data[i+2];
            offset &= (BUF_SIZE - 1);
            acc ^= data[offset];
        } else acc += 0xDEADBEEF;
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

        if (isComp) RunCompilerLogic(idx, w);
        else if (isDec) RunDecompressLogic(idx, w);
        else std::this_thread::sleep_for(10ms);

        w.lastTick = GetTick();
    }
}

void IOThread(int ioIdx) {
    DisablePowerThrottling();
    auto& w = *g_IOThreads[ioIdx];

    wchar_t path[MAX_PATH]; GetTempPathW(MAX_PATH, path);
    std::wstring fpath = std::wstring(path) + L"stress_" + std::to_wstring(ioIdx) + L".tmp";
    {
        std::ofstream f(fpath, std::ios::binary);
        std::vector<char> junk(1024*1024, 'x');
        for(int i=0; i<(IO_FILE_SIZE/(1024*1024)); ++i) f.write(junk.data(), junk.size());
    }

    ScopedHandle hFile(CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr));
    ScopedMem buf(IO_CHUNK_SIZE);
    std::mt19937_64 rng(GetTick() + ioIdx);

    while(!w.terminate) {
        if (!g_App.ioActive && !g_Repro.active) { std::this_thread::sleep_for(100ms); continue; }
        if(hFile == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(1s); continue; }

        LARGE_INTEGER pos;
        pos.QuadPart = (rng() % (IO_FILE_SIZE - IO_CHUNK_SIZE)) & ~4095;
        SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN);

        DWORD read;
        uint8_t* p = buf.As<uint8_t>();
        if(ReadFile(hFile, p, (DWORD)IO_CHUNK_SIZE, &read, nullptr) && read > 0) {
            volatile uint8_t sink = p[0] ^ p[read-1]; (void)sink;
        }
        w.lastTick = GetTick();
    }
    DeleteFileW(fpath.c_str());
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

        if (safeSize < 1024 * 1024) { std::this_thread::sleep_for(1s); continue; }

        ScopedMem mem(safeSize);
        if(mem.ptr) {
            uint64_t* p = mem.As<uint64_t>();
            size_t count = safeSize / sizeof(uint64_t);
            for(size_t i = 0; i < count; i += 16) { p[i] = (i + 16) % count; }

            uint64_t burstEnd = GetTick() + 5000;
            while (GetTick() < burstEnd && !w.terminate && g_App.ramActive) {
                if (rng() % 2 == 0) {
                    size_t stride = 64;
                    for(size_t i=0; i < count; i += stride) { p[i] = (i + 16) % count; }
                } else {
                    volatile uint64_t idx = 0;
                    for(int k=0; k<100000; ++k) { idx = p[idx]; }
                }
                w.lastTick = GetTick();
            }
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
    for (int i = 0; i < ms; i += 20) {
        if (!g_App.running || g_App.mode != 2) return;
        std::this_thread::sleep_for(20ms);
    }
}

struct PhaseState {
    bool toggle2 = false;
    bool toggle4 = false;
};

void DynamicLoop() {
    DisablePowerThrottling();
    int cpu = (int)g_Workers.size();
    int pIdx = 0;
    PhaseState state;

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
                case 2: { state.toggle2 = !state.toggle2; if (state.toggle2) SetStrict(0, 0, false, false); else SetStrict(std::max(0, cpu - 4), 2, true, true); SmartSleep(500); } break;
                case 3: SetStrict(0, std::max(0, cpu - 2), true, true); SmartSleep(100); break;
                case 4: { state.toggle4 = !state.toggle4; if (state.toggle4) SetStrict(0, 0, false, false); else SetStrict(0, std::max(0, cpu - 2), true, true); SmartSleep(500); } break;
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
    uint64_t runStart = 0;
    bool warmingUp = false, lastRunning = false;
    uint64_t benchIntervalStartShaders = 0;
    int lastBenchIntervalIndex = -1;

    uint64_t lastRateTime = GetTick();
    uint64_t lastRateShaders = 0;

    while(!g_App.quit) {
        bool currentRunning = g_App.running;
        uint64_t now = GetTick();
        uint64_t totalShaders = 0;
        for(const auto& w : g_Workers) totalShaders += w->localShaders.load(std::memory_order_relaxed);
        g_App.shaders = totalShaders;

        if (g_App.resetTimer.exchange(false)) {
            g_App.elapsed = 0; runStart = now; warmingUp = true;
            g_App.currentRate = 0;
            benchIntervalStartShaders = g_App.shaders;
            lastBenchIntervalIndex = -1;
            g_App.benchWinner = -1; g_App.benchComplete = false;
            for(int i=0; i<3; ++i) g_App.benchRates[i] = 0;
            lastRateTime = now;
            lastRateShaders = g_App.shaders;
        }

        if (currentRunning && !lastRunning) {
            g_App.resetTimer = true;
        }
        lastRunning = currentRunning;

        if(currentRunning) {
            if (g_App.elapsed == 0 && runStart == 0) {
                runStart = now; benchIntervalStartShaders = g_App.shaders;
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
                if (dt > 0) g_App.currentRate = (dShader * 1000) / dt;
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
                        g_App.Log(L"Benchmark Minute " + std::to_wstring(lastBenchIntervalIndex + 1) + L": " + FmtNum(g_App.benchRates[lastBenchIntervalIndex]) + L" Jobs/s");
                    }
                    lastBenchIntervalIndex = currentIntervalIdx;
                }

                if (g_App.elapsed >= BENCHMARK_DURATION_SEC && !g_App.benchComplete) {
                    g_App.benchComplete = true;
                    uint64_t r0 = g_App.benchRates[0];
                    uint64_t r1 = g_App.benchRates[1];
                    uint64_t r2 = g_App.benchRates[2];

                    if (r0 >= r1 && r0 >= r2) g_App.benchWinner = 0;
                    else if (r1 >= r0 && r1 >= r2) g_App.benchWinner = 1;
                    else g_App.benchWinner = 2;

                    std::wstringstream report;
                    report << L"\n========================================\n";
                    report << L"Shader Stress " << APP_VERSION << L" Benchmark Result\n";
                    report << L"CPU: " << g_Cpu.brand << L"\n";
                    report << L"Workload: Scalar real.\n";
                    report << L"----------------------------------------\n";
                    report << L"Minute 1: " << FmtNum(r0) << L" Jobs/s\n";
                    report << L"Minute 2: " << FmtNum(r1) << L" Jobs/s\n";
                    report << L"Minute 3: " << FmtNum(r2) << L" Jobs/s\n";
                    report << L"----------------------------------------\n";
                    report << L"WINNER: Interval " << (g_App.benchWinner + 1) << L" (" << FmtNum(g_App.benchRates[g_App.benchWinner]) << L" Jobs/s)\n";
                    report << L"========================================";

                    g_App.LogRaw(report.str());
                    g_App.Log(L"Benchmark Finished. Winner: Interval " + std::to_wstring(g_App.benchWinner + 1));
                    if(g_MainWindow) InvalidateRect(g_MainWindow, nullptr, FALSE);
                }
            }

            if (g_App.maxDuration.load() > 0 && runStart > 0) {
                if ((now - runStart)/1000 >= g_App.maxDuration.load()) {
                    g_App.running = false;
                    g_App.Log(L"Max duration reached. Stopping.");
                    if(g_MainWindow) InvalidateRect(g_MainWindow, nullptr, FALSE);
                }
            }
        } else {
            runStart = 0;
        }

        std::this_thread::sleep_for(500ms);
        if(g_MainWindow && (g_App.running || g_App.benchComplete) && !IsIconic(g_MainWindow)) InvalidateRect(g_MainWindow, nullptr, FALSE);
    }
}

HFONT g_Font = nullptr;
HBRUSH g_BgBrush = nullptr;
HBRUSH g_BtnActive = nullptr;
HBRUSH g_BtnInactive = nullptr;
HBRUSH g_BtnDisabled = nullptr;

void InitGDI() {
    g_Font = CreateFontW(-(int)(16 * g_Scale), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
    g_BgBrush = CreateSolidBrush(RGB(20,20,20));
    g_BtnActive = CreateSolidBrush(RGB(60,100,160));
    g_BtnInactive = CreateSolidBrush(RGB(50,50,50));
    g_BtnDisabled = CreateSolidBrush(RGB(30,30,30));
}
void CleanupGDI() {
    DeleteObject(g_Font); DeleteObject(g_BgBrush);
    DeleteObject(g_BtnActive); DeleteObject(g_BtnInactive); DeleteObject(g_BtnDisabled);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if(m == WM_DESTROY) {
        g_App.running = false; g_App.quit = true; PostQuitMessage(0); return 0;
    }
    if(m == WM_PAINT) {
        PAINTSTRUCT ps; BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);

        static HDC s_memDC = nullptr;
        static HBITMAP s_memBM = nullptr;
        static int s_width = 0, s_height = 0;

        if (rc.right != s_width || rc.bottom != s_height || !s_memDC) {
            if (s_memDC) { DeleteDC(s_memDC); DeleteObject(s_memBM); }
            s_memDC = CreateCompatibleDC(ps.hdc);
            s_memBM = CreateCompatibleBitmap(ps.hdc, rc.right, rc.bottom);
            SelectObject(s_memDC, s_memBM);
            s_width = rc.right; s_height = rc.bottom;
        }

        FillRect(s_memDC, &rc, g_BgBrush);
        SetBkMode(s_memDC, TRANSPARENT); SetTextColor(s_memDC, RGB(200,200,200));
        HFONT oldFont = (HFONT)SelectObject(s_memDC, g_Font);

        auto btn = [&](int id, const wchar_t* txt, int x, int y, bool active, bool enabled = true) {
            RECT r{x, y, x+S(140), y+S(30)};
            HBRUSH b = enabled ? (active ? g_BtnActive : g_BtnInactive) : g_BtnDisabled;
            FillRect(s_memDC, &r, b);

            if (!enabled) SetTextColor(s_memDC, RGB(80,80,80));
            DrawTextW(s_memDC, txt, -1, &r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            if (!enabled) SetTextColor(s_memDC, RGB(200,200,200));
        };

            bool run = g_App.running;
            btn(1, run ? L"STOP" : L"START", S(10), S(10), run);
            btn(2, L"Dynamic", S(160), S(10), g_App.mode==2);
            btn(3, L"Steady", S(310), S(10), g_App.mode==1);
            btn(4, L"Benchmark", S(460), S(10), g_App.mode==0);
            btn(5, L"Close", S(610), S(10), false);

            int y2 = S(50);
            int sel = g_App.selectedWorkload;
            #if defined(_M_ARM64)
            bool has512 = false;
            bool hasAVX2 = false;
            #else
            bool has512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
            bool hasAVX2 = g_Cpu.hasAVX2 && !g_ForceNoAVX2;
            #endif

            btn(10, L"Auto", S(10), y2, sel==WL_AUTO);
            btn(11, L"AVX-512 (synthetic)", S(160), y2, sel==WL_AVX512, has512);
            btn(12, L"AVX2 (synthetic)", S(310), y2, sel==WL_AVX2, hasAVX2);
            btn(13, L"Scalar (synthetic)", S(460), y2, sel==WL_SCALAR_MATH);
            btn(14, L"Scalar (realistic)", S(610), y2, sel==WL_SCALAR_SIM);

            std::wstring modeName = (g_App.mode == 2 ? L"Dynamic" : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
            std::wstring activeISA = L"Unknown";
            if (sel == WL_SCALAR_MATH) activeISA = L"Scalar synthetic (Forced)";
            else if (sel == WL_SCALAR_SIM) activeISA = L"Scalar realistic (Forced)";
            else if (sel == WL_AVX2) activeISA = L"AVX2 synthetic (Forced)";
            else if (sel == WL_AVX512) activeISA = L"AVX-512 synthetic (Forced)";
            else {
                if (has512) activeISA = L"AVX-512 synthetic (Auto)";
                else if (hasAVX2) activeISA = L"AVX2 synthetic (Auto)";
                else activeISA = L"Scalar realistic (Auto)";
            }

            std::wstring part1 = L"Shader Stress " + APP_VERSION + L"\nMode: " + modeName + L"\nActive ISA: " + activeISA +
            L"\nJobs Done: " + FmtNum(g_App.shaders) +
            L"\n\n--- Performance ---\nRate (Jobs/s): " + FmtNum(g_App.currentRate) + L"\nTime: " + FmtTime(g_App.elapsed);

            if (g_App.mode == 2) {
                part1 += L"\nPhase: " + std::to_wstring(g_App.currentPhase) + L" / 15";
                part1 += L"\nLoop: " + std::to_wstring(g_App.loops);
            } else if (g_App.mode == 0) {
                part1 += L"\n\n--- Benchmark Rounds (60s each) ---";
                part1 += L"\n1st Minute: " + (g_App.benchRates[0] > 0 ? FmtNum(g_App.benchRates[0]) : (g_App.elapsed < 60 && run ? L"Running..." : L"-"));
                part1 += L"\n2nd Minute: " + (g_App.benchRates[1] > 0 ? FmtNum(g_App.benchRates[1]) : (g_App.elapsed >= 60 && g_App.elapsed < 120 && run ? L"Running..." : L"-"));
                part1 += L"\n3rd Minute: " + (g_App.benchRates[2] > 0 ? FmtNum(g_App.benchRates[2]) : (g_App.elapsed >= 120 && g_App.elapsed < 180 && run ? L"Running..." : L"-"));
                if (g_App.benchComplete && g_App.benchWinner != -1) {
                    part1 += L"\n\nWINNER: Interval " + std::to_wstring(g_App.benchWinner + 1);
                    part1 += L"\n(Results written to ShaderStress.log)";
                }
            }

            std::wstring partError = L"Errors: " + FmtNum(g_App.errors);
            std::wstring part3 = L"\n\n--- Stress Status ---";
            part3 += L"\nWorker Threads: " + FmtNum(g_App.activeCompilers + g_App.activeDecomp);
            part3 += L"\n  > Sim Compilers: " + FmtNum(g_App.activeCompilers);
            part3 += L"\n  > Decompressors: " + FmtNum(g_App.activeDecomp);
            part3 += L"\nRAM Thread: " + std::wstring(g_App.ramActive ? L"ACTIVE" : L"Idle");
            part3 += L"\nI/O Threads: " + std::wstring(g_App.ioActive ? L"ACTIVE (4x)" : L"Idle");

            RECT tr{S(20), S(100), S(740), S(620)};
            DrawTextW(s_memDC, part1.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
            RECT measure = tr; DrawTextW(s_memDC, part1.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT); tr.top += (measure.bottom - measure.top);

            if(g_App.errors > 0) SetTextColor(s_memDC, RGB(255, 80, 80)); else SetTextColor(s_memDC, RGB(80, 255, 80));
            DrawTextW(s_memDC, partError.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
        measure = tr; DrawTextW(s_memDC, partError.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT); tr.top += (measure.bottom - measure.top);

        SetTextColor(s_memDC, RGB(200, 200, 200));
        DrawTextW(s_memDC, part3.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);

        BitBlt(ps.hdc, 0, 0, rc.right, rc.bottom, s_memDC, 0, 0, SRCCOPY);
        SelectObject(s_memDC, oldFont);
        EndPaint(h, &ps); return 0;
    }
    if(m == WM_LBUTTONDOWN) {
        int x = GET_X_LPARAM(l);
        int y = GET_Y_LPARAM(l);

        if(y > S(10) && y < S(40)) {
            bool clickedStart = (x > S(10) && x < S(150));
            int newMode = -1;
            if (x > S(160) && x < S(300)) newMode = 2;
            else if (x > S(310) && x < S(450)) newMode = 1;
            else if (x > S(460) && x < S(600)) newMode = 0;
            else if (x > S(610) && x < S(750)) PostMessage(h, WM_CLOSE, 0, 0);

            std::lock_guard<std::mutex> lock(g_StateMtx);

            auto StartWorkload = []() {
                if(g_DynThread && g_DynThread->t.joinable()) g_DynThread->t.join();
                if (g_App.mode == 2) {
                    g_DynThread = std::make_unique<ThreadWrapper>();
                    g_DynThread->t = std::thread(DynamicLoop);
                } else if (g_App.mode == 1) {
                    int cpu = (int)g_Workers.size();
                    int d = std::min(4, std::max(1, cpu / 2));
                    int c = std::max(0, cpu - d);
                    SetWork(c, d, true, true);
                } else {
                    for(int i=0; i<3; ++i) g_App.benchRates[i] = 0;
                    g_App.benchWinner = -1; g_App.benchComplete = false;
                    SetWork((int)g_Workers.size(), 0, 0, 0);
                }
            };

            auto ResetState = []() {
                g_App.shaders=0; g_App.elapsed=0; g_App.totalNodes=0; g_App.loops=0; g_App.currentPhase=0;
                for(auto& w : g_Workers) w->localShaders = 0;
            };

                if (clickedStart) {
                    g_App.running = !g_App.running;
                    if(g_App.running) {
                        g_App.Log(L"State changed: STARTED");
                        ResetState();
                        StartWorkload();
                    } else {
                        g_App.Log(L"State changed: STOPPED");
                        SetWork(0,0,0,0);
                    }
                } else if (newMode != -1 && newMode != g_App.mode) {
                    g_App.mode = newMode;
                    if (newMode == 0) g_App.selectedWorkload = WL_SCALAR_SIM;
                    else g_App.selectedWorkload = WL_AUTO;

                    if(g_App.running) {
                        ResetState();
                        StartWorkload();
                    }
                }
                g_App.resetTimer = true; InvalidateRect(h, nullptr, FALSE);
        }
        if (y > S(50) && y < S(80)) {
            #if defined(_M_ARM64)
            bool has512 = false;
            bool hasAVX2 = false;
            #else
            bool has512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
            bool hasAVX2 = g_Cpu.hasAVX2 && !g_ForceNoAVX2;
            #endif
            int newSel = -1;
            if (x > S(10) && x < S(150)) newSel = WL_AUTO;
            else if (x > S(160) && x < S(300) && has512) newSel = WL_AVX512;
            else if (x > S(310) && x < S(450) && hasAVX2) newSel = WL_AVX2;
            else if (x > S(460) && x < S(600)) newSel = WL_SCALAR_MATH;
            else if (x > S(610) && x < S(750)) newSel = WL_SCALAR_SIM;

            if (newSel != -1 && newSel != g_App.selectedWorkload) {
                g_ConfigVersion++;
                g_App.selectedWorkload = newSel;
                if (g_App.running) {
                    g_App.resetTimer = true;
                }
                InvalidateRect(h, nullptr, FALSE);
            }
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
    AllocConsole(); freopen("CONOUT$", "w", stdout);
    _wprintf_p(L"ShaderStress v%ls\n\n", APP_VERSION.c_str());
    printf("Options:\n  --repro <seed> <complexity>  : Run a specific crash reproduction case.\n  --max-duration <sec>         : Automatically stop after N seconds.\n  --no-avx512                  : Force AVX2/Scalar path.\n  --no-avx2                    : Force Scalar path.\n");
    getchar(); ExitProcess(0);
}

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_Scale = GetDpiForSystem() / 96.0f;
    g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
    g_App.log.imbue(std::locale(""));
    g_Cpu = GetCpuInfo();
    g_App.sigStatus = g_Cpu.name;

    g_ColdStorage.resize(32 * 1024 * 1024 / 8);
    std::mt19937_64 r(123); for(auto& v : g_ColdStorage) v = r();

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--repro") == 0 && i + 2 < argc) {
                g_Repro.active = true;
                g_Repro.seed = _wtoi64(argv[i+1]);
                g_Repro.complexity = _wtoi(argv[i+2]);
            }
            if (lstrcmpiW(argv[i], L"--max-duration") == 0 && i + 1 < argc) g_App.maxDuration = _wtoi(argv[i+1]);
            if (lstrcmpiW(argv[i], L"--no-avx512") == 0) g_ForceNoAVX512 = true;
            if (lstrcmpiW(argv[i], L"--no-avx2") == 0) g_ForceNoAVX2 = true;
            if (lstrcmpiW(argv[i], L"--help") == 0) PrintHelp();
        }
        LocalFree(argv);
    }
    DetectBestConfig();

    int cpu = std::thread::hardware_concurrency(); if(cpu == 0) cpu = 4;
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
    { auto t = std::make_unique<ThreadWrapper>(); t->t = std::thread(RAMThread); g_Threads.push_back(std::move(t)); }

    if (g_Repro.active) {
        g_App.Log(L"Repro Mode Active. Running workload...");
        std::this_thread::sleep_for(11s);
        g_App.Log(L"Repro finished without crash.");
        goto cleanup;
    }

    g_WdThread = std::make_unique<ThreadWrapper>();
    g_WdThread->t = std::thread(Watchdog);

    {
        WNDCLASSW wc{0, WndProc, 0, 0, inst, nullptr, LoadCursor(0, IDC_ARROW), nullptr, nullptr, L"SST"};
        wc.hIcon = LoadIconW(inst, MAKEINTRESOURCE(1)); RegisterClassW(&wc);
        InitGDI();

        RECT rc = {0, 0, S(760), S(620)};
        DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
        AdjustWindowRect(&rc, style, FALSE);
        int wW = rc.right - rc.left;
        int wH = rc.bottom - rc.top;

        g_MainWindow = CreateWindowW(L"SST", L"Shader Stress", style,
                                     (GetSystemMetrics(SM_CXSCREEN)-wW)/2, (GetSystemMetrics(SM_CYSCREEN)-wH)/2, wW, wH, 0, 0, inst, 0);

        BOOL useDark = TRUE; DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));
        MSG msg; while(GetMessage(&msg, 0, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
        CleanupGDI();
    }

    cleanup:
    g_App.quit = true;
    for(auto& w : g_Workers) w->terminate = true;
    for(auto& w : g_IOThreads) w->terminate = true;
    g_RAM.terminate = true;
    g_DynThread.reset(); g_WdThread.reset();
    g_Threads.clear();
    return 0;
}
