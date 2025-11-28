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

#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "dwmapi")
#pragma comment(lib, "shcore")
#pragma comment(lib, "shell32")
#pragma comment(lib, "dbghelp")

namespace fs = std::filesystem;
using namespace std::chrono_literals;

const std::wstring APP_VERSION = L"1.0";

const char* LICENSE_TEXT = R"(MIT License

Copyright (c) 2025 aufkrawall

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
)";

// --- Helpers & Global State ---
static inline uint64_t Rotl64(uint64_t v, unsigned r) { return (v << r) | (v >> (64u - r)); }
static inline uint64_t GetTick() { return GetTickCount64(); }
std::wstring FmtNum(uint64_t v) { std::wstringstream s; s.imbue(std::locale("")); s << v; return s.str(); }
std::wstring FmtTime(uint64_t s) {
    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(2) << (s/3600) << L":" << std::setw(2) << ((s%3600)/60) << L":" << std::setw(2) << (s%60);
    return ss.str();
}

struct CpuFeatures {
    bool hasAVX2 = false;
    bool hasAVX512F = false;
    std::wstring name;
};

CpuFeatures GetCpuInfo() {
    CpuFeatures f;
    int regs[4];
    __cpuid(regs, 0);
    int nIds = regs[0];
    if (nIds >= 7) {
        __cpuidex(regs, 7, 0);
        f.hasAVX2 = (regs[1] & (1 << 5)) != 0;
        f.hasAVX512F = (regs[1] & (1 << 16)) != 0;
    }
    if (f.hasAVX512F) f.name = L"AVX-512";
    else if (f.hasAVX2) f.name = L"AVX2";
    else f.name = L"SSE/Legacy";
    return f;
}

CpuFeatures g_Cpu;

struct AppState {
    std::atomic<bool> running{false}, quit{false};
    std::atomic<int> mode{2}, activeCompilers{0}, activeDecomp{0}, loops{0};
    std::atomic<bool> ioActive{false}, ramActive{false};
    std::atomic<bool> resetTimer{false};
    std::atomic<int> currentPhase{0}; // For UI display (1-12)

    std::atomic<uint64_t> shaders{0};
    std::atomic<uint64_t> totalNodes{0};
    std::atomic<uint64_t> errors{0}, elapsed{0};

    std::atomic<uint64_t> currentRate{0};
    std::atomic<uint64_t> nodeRate{0};
    std::atomic<uint64_t> bestOf3{0};
    std::deque<uint64_t> last3Rates;
    std::mutex metricsMtx;

    std::wstring sigStatus;
    std::wofstream log;
    std::mutex logMtx;

    void Log(const std::wstring& msg) {
        std::lock_guard<std::mutex> lk(logMtx);
        if(log.is_open()) {
            SYSTEMTIME t; GetSystemTime(&t);
            log << L"[" << t.wHour << L":" << t.wMinute << L":" << t.wSecond << L"." << t.wMilliseconds << L"] " << msg << std::endl;
            log.flush();
        }
    }
} g_App;

HWND g_MainWindow = nullptr;
std::thread g_DynThread;
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
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d_%H-%M-%S");

    std::string folderName = "Crash_" + ss.str() + "_Thread" + std::to_string(threadIdx);
    fs::create_directories(folderName);
    fs::path basePath = fs::path(folderName);

    // Log the crash before terminating
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
        std::ofstream info(basePath / "crash_seed.txt");
        info << "Seed: " << seed << "\n";
        info << "Complexity: " << complexity << "\n";
        info << "Thread: " << threadIdx << "\n";
    }

    {
        std::ofstream bat(basePath / "repro.bat");
        bat << "@echo off\n";
        bat << "echo [REPRO] Launching ShaderStress in Console Mode...\n";
        bat << "..\\ShaderStress.exe --repro " << seed << " " << complexity << "\n";
        bat << "pause\n";
    }

    {
        std::ofstream bat(basePath / "analyze.bat");
        bat << "@echo off\n";
        bat << "set DUMPFILE=crash.dmp\n";
        bat << "if exist \"C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe\" (\n";
        bat << "    \"C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe\" -y \"srv*https://msdl.microsoft.com/download/symbols\" -z \"%DUMPFILE%\" -c \"!analyze -v; q\"\n";
        bat << ") else ( echo CDB not found. Open crash.dmp in Visual Studio manually. )\n";
        bat << "pause\n";
    }

    std::wstring msg = L"FATAL CRASH in Thread " + std::to_wstring(threadIdx);
    OutputDebugStringW(msg.c_str());
    return EXCEPTION_EXECUTE_HANDLER;
}

// --- SYNTHETIC COMPILER LOGIC ---
enum NodeType : uint8_t { NT_ADD, NT_SUB, NT_MUL, NT_LOAD, NT_STORE, NT_BRANCH, NT_PHI };

struct ASTNode {
    uint64_t value;
    int32_t children[3];
    NodeType type;
    uint8_t childCount;
    int8_t regTarget;
    uint8_t padding;
    ASTNode(NodeType t, uint64_t v) : value(v), type(t), childCount(0), regTarget(-1), padding(0) { children[0] = children[1] = children[2] = -1; }
};

struct BasicBlock { int startNodeIdx; int count; int nextBlockIdx = -1; };

void RunAVX512_Kernel(float* data, size_t count) {
    if (count < 64) return;
    __m512 acc0 = _mm512_set1_ps(1.00001f); __m512 acc1 = _mm512_set1_ps(0.99999f);
    __m512 acc2 = _mm512_set1_ps(1.00002f); __m512 acc3 = _mm512_set1_ps(0.99998f);
    __m512 c = _mm512_set1_ps(0.5f);
    for (size_t i = 0; i + 64 <= count; i += 64) {
        __m512 v0 = _mm512_loadu_ps(&data[i]); __m512 v1 = _mm512_loadu_ps(&data[i+16]);
        __m512 v2 = _mm512_loadu_ps(&data[i+32]); __m512 v3 = _mm512_loadu_ps(&data[i+48]);
        for (int k = 0; k < 32; ++k) {
            acc0 = _mm512_fmadd_ps(acc0, v0, c); acc1 = _mm512_fmadd_ps(acc1, v1, c);
            acc2 = _mm512_fmadd_ps(acc2, v2, c); acc3 = _mm512_fmadd_ps(acc3, v3, c);
            v0 = _mm512_fmadd_ps(v0, c, acc3); v1 = _mm512_fmadd_ps(v1, c, acc2);
        }
        _mm512_storeu_ps(&data[i], acc0); _mm512_storeu_ps(&data[i+16], acc1);
        _mm512_storeu_ps(&data[i+32], acc2); _mm512_storeu_ps(&data[i+48], acc3);
    }
}

void RunAVX2_Kernel(float* data, size_t count) {
    if (count < 32) return;
    __m256 acc0 = _mm256_set1_ps(1.00001f); __m256 acc1 = _mm256_set1_ps(0.99999f);
    __m256 acc2 = _mm256_set1_ps(1.00002f); __m256 acc3 = _mm256_set1_ps(0.99998f);
    __m256 c = _mm256_set1_ps(0.5f);
    for (size_t i = 0; i + 32 <= count; i += 32) {
        __m256 v0 = _mm256_loadu_ps(&data[i]); __m256 v1 = _mm256_loadu_ps(&data[i+8]);
        __m256 v2 = _mm256_loadu_ps(&data[i+16]); __m256 v3 = _mm256_loadu_ps(&data[i+24]);
        for (int k = 0; k < 32; ++k) {
            acc0 = _mm256_fmadd_ps(acc0, v0, c); acc1 = _mm256_fmadd_ps(acc1, v1, c);
            acc2 = _mm256_fmadd_ps(acc2, v2, c); acc3 = _mm256_fmadd_ps(acc3, v3, c);
            v0 = _mm256_fmadd_ps(v0, c, acc3); v1 = _mm256_fmadd_ps(v1, c, acc2);
        }
        _mm256_storeu_ps(&data[i], acc0); _mm256_storeu_ps(&data[i+8], acc1);
        _mm256_storeu_ps(&data[i+16], acc2); _mm256_storeu_ps(&data[i+24], acc3);
    }
}

void RunGeneric_Kernel(float* data, size_t count) {
    float acc = 1.01f;
    for (size_t i = 0; i < count; ++i) {
        float v = data[i];
        for(int k=0; k<20; ++k) { acc = (acc * v) + 0.5f; v = (v * 0.99f) + 0.01f; }
        data[i] = acc;
    }
}

class SyntheticCompiler {
    std::mt19937 rng;
    std::vector<ASTNode> nodes;
    std::vector<BasicBlock> blocks;
    std::vector<float> vectorRegisterFile;

public:
    SyntheticCompiler(uint64_t seed) : rng((unsigned)seed) {}

    void BuildAST(int complexity) {
        nodes.reserve(complexity);
        blocks.reserve(complexity / 10);
        BasicBlock currentBlock; currentBlock.startNodeIdx = 0; currentBlock.count = 0;

        std::discrete_distribution<int> typeDist({40, 40, 40, 30, 10, 5, 5});

        for (int i = 0; i < complexity; ++i) {
            // Optimization: Check for global quit during heavy generation
            // Using bitwise AND for speed (every 1024 iterations)
            if ((i & 0x3FF) == 0 && g_App.quit) return;

            NodeType type = (NodeType)typeDist(rng);
            nodes.emplace_back(type, rng());
            ASTNode& node = nodes.back();

            if (i > 0) {
                std::discrete_distribution<int> childDist({10, 60, 20, 10});
                node.childCount = childDist(rng);
                for (int k = 0; k < node.childCount; ++k) node.children[k] = rng() % i;
            }

            currentBlock.count++;

            if (i > 0 && (rng() % 30) == 0) {
                currentBlock.nextBlockIdx = (int)blocks.size() + 1;
                blocks.push_back(currentBlock);
                currentBlock.startNodeIdx = i + 1; currentBlock.count = 0; currentBlock.nextBlockIdx = -1;
            }
        }
        blocks.push_back(currentBlock);
    }

    void Optimize() {
        for (int pass = 0; pass < 2; ++pass) {
            for (auto& block : blocks) {
                // Quick check in outer optimization loops
                if (g_App.quit) return;

                for (int i = 0; i < block.count; ++i) {
                    int nodeIdx = block.startNodeIdx + i;
                    if (nodeIdx >= (int)nodes.size()) break;
                    ASTNode& node = nodes[nodeIdx];
                    uint64_t hash = 0;
                    for (int k = 0; k < node.childCount; ++k) {
                        int childIdx = node.children[k];
                        if (childIdx >= 0) {
                            ASTNode& child = nodes[childIdx];
                            uint64_t v = child.value;
                            v ^= v << 13; v ^= v >> 7; v ^= v << 17;
                            hash += v * 0x2545F4914F6CDD1Dull;
                            child.value = v;
                        }
                    }
                    node.value = (node.value ^ hash) * 6364136223846793005ull;
                }
            }
        }

        size_t vecSize = nodes.size() * 32;
        if (vecSize > 4*1024*1024) vecSize = 4*1024*1024;
        vectorRegisterFile.resize(vecSize);

        int heatPasses = 0;
        bool pulseMode = false;

        if (g_App.mode == 1) {
            heatPasses = 40;
            pulseMode = false;
        } else {
            heatPasses = 5 + (rng() % 5);
            pulseMode = (rng() % 3) == 0;
        }

        for(int p=0; p<heatPasses; ++p) {
            // CRITICAL: Emergency Brake for shutdown latency
            if (g_App.quit) break;

            if (pulseMode && (p % 2 == 0)) {
                std::this_thread::yield();
            }

            if (g_Cpu.hasAVX512F) RunAVX512_Kernel(vectorRegisterFile.data(), vecSize);
            else if (g_Cpu.hasAVX2) RunAVX2_Kernel(vectorRegisterFile.data(), vecSize);
            else RunGeneric_Kernel(vectorRegisterFile.data(), vecSize);
        }
    }

    void Emit(std::vector<uint8_t>& buffer) {
        if (g_App.quit) return; // Don't emit if quitting
        buffer.reserve(nodes.size() * 8);
        for (const auto& node : nodes) {
            buffer.push_back((uint8_t)node.type);
            uint64_t v = node.value;
            for(int k=0; k<8; ++k) buffer.push_back((v >> (k*8)) & 0xFF);
        }
    }
};

void UnsafeRunWorkload(uint64_t seed, int complexity, std::vector<uint8_t>* buffer) {
    SyntheticCompiler compiler(seed);
    compiler.BuildAST(complexity);
    if (g_App.quit) return; // Abort early
    compiler.Optimize();
    if (g_App.quit) return; // Abort early
    buffer->clear();
    compiler.Emit(*buffer);
}

void SafeRunWorkload(uint64_t seed, int complexity, std::vector<uint8_t>& buffer, int threadIdx) {
    __try {
        UnsafeRunWorkload(seed, complexity, &buffer);
    }
    __except(WriteCrashDump(GetExceptionInformation(), seed, complexity, threadIdx)) {
        ExitProcess(-1);
    }
}

void RunReproMode(uint64_t seed, int complexity) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    printf("Running Repro: Seed %llu\n", seed);
    DisablePowerThrottling();
    std::vector<uint8_t> buffer;
    UnsafeRunWorkload(seed, complexity, &buffer);
    printf("Finished.\n");
    getchar();
    ExitProcess(0);
}

// --- WORKER INFRASTRUCTURE ---
struct Worker {
    std::thread t; std::mutex mtx; std::condition_variable cv;
    std::atomic<bool> active{false}, terminate{false}; std::atomic<uint64_t> lastTick{0};
    void Start(bool run) { bool current = active.load(); if (current != run) { active.store(run); if (run) cv.notify_one(); } }
    bool Wait() { if (terminate.load()) return false; if (active.load()) return true; std::unique_lock<std::mutex> lk(mtx); cv.wait(lk, [this]{ return terminate.load() || active.load(); }); return !terminate.load(); }
};

std::vector<std::unique_ptr<Worker>> g_Compilers, g_Decompress;
Worker g_IO, g_RAM;

void CompilerThread(int idx) {
    DisablePowerThrottling();
    std::this_thread::sleep_for(std::chrono::milliseconds(idx * 50));
    auto& w = *g_Compilers[idx];
    std::vector<uint8_t> outputBuffer;

    std::mt19937 gen(1234 + idx);
    std::exponential_distribution<> expDist(0.0001);

    while(!w.terminate) {
        if(!w.Wait()) break;
        while(w.active && !w.terminate) {
            uint64_t id = g_App.shaders.fetch_add(1, std::memory_order_relaxed);

            std::random_device rd;
            std::mt19937_64 seedMixer(rd() ^ (uint64_t)GetTick() ^ (uint64_t)idx);
            uint64_t seed = seedMixer();

            int complexity = 0;
            if (g_App.mode == 1) {
                complexity = 50000;
            } else {
                complexity = 5000 + (int)expDist(gen);
                if (complexity > 2000000) complexity = 2000000;
            }

            SafeRunWorkload(seed, complexity, outputBuffer, idx);

            g_App.totalNodes.fetch_add(complexity, std::memory_order_relaxed);
            if (!outputBuffer.empty() && outputBuffer[0] == 0xFF) g_App.Log(L"Rare Byte");
            w.lastTick = GetTick();
        }
    }
}

void DecompressThread(int idx) {
    DisablePowerThrottling();
    auto& w = *g_Decompress[idx];
    std::vector<uint64_t> data(16384);
    std::mt19937_64 rng(idx * 999);
    while(!w.terminate) {
        if(!w.Wait()) break;
        while(w.active && !w.terminate) {
            // Add check to exit tight loop
            if (w.terminate) break;
            for(auto& v : data) v = Rotl64(v ^ rng(), 13) * 0x9E3779B97F4A7C15ull;
            w.lastTick = GetTick();
        }
    }
}

void IOThread() {
    DisablePowerThrottling();
    auto& w = g_IO;
    wchar_t path[MAX_PATH]; GetTempPathW(MAX_PATH, path);
    std::wstring fpath = std::wstring(path) + L"stress.tmp";
    { std::ofstream f(fpath, std::ios::binary); std::vector<char> junk(1024*1024, 'x'); for(int i=0; i<128; ++i) f.write(junk.data(), junk.size()); }
    HANDLE hFile = CreateFileW(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
    auto* buf = (uint64_t*)VirtualAlloc(nullptr, 4*1024*1024, MEM_COMMIT, PAGE_READWRITE);
    while(!w.terminate) {
        if(!w.Wait()) break;
        if(hFile == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(1s); continue; }
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        while(w.active && !w.terminate) {
            // Add check to exit tight loop
            if (w.terminate) break;
            DWORD read;
            if(ReadFile(hFile, buf, 4*1024*1024, &read, nullptr) && read > 0) {
                uint64_t acc = 0;
                for(int pass=0; pass<16; ++pass) for(DWORD i=0; i<read/8; ++i) acc += Rotl64(buf[i], pass) * 0xC2B2AE3D27D4EB4Full;
                if(acc == 1) g_App.Log(L"Magic");
            } else SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
            w.lastTick = GetTick();
        }
    }
    CloseHandle(hFile); DeleteFileW(fpath.c_str());
}

void RAMThread() {
    DisablePowerThrottling();
    auto& w = g_RAM;
    while(!w.terminate) {
        if(!w.Wait()) break;
        MEMORYSTATUSEX ms{sizeof(ms)}; GlobalMemoryStatusEx(&ms);
        size_t size = (size_t)(ms.ullTotalPhys * 7 / 10);
        uint64_t* mem = (uint64_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
        if(mem) {
            while(w.active && !w.terminate) {
                // Add check to exit tight loop
                if (w.terminate) break;
                size_t stride = 128; uint64_t acc = 0xDEADBEEF;
                for(size_t i=0; i < size/8; i += stride) { uint64_t v = mem[i]; v ^= acc; v = Rotl64(v, 7) * 0x9E3779B97F4A7C15ull; mem[i] = v; acc += v; }
                w.lastTick = GetTick();
            }
            VirtualFree(mem, 0, MEM_RELEASE);
        } else std::this_thread::sleep_for(1s);
    }
}

// Helper to strictly enforce thread limits
void SetWork(int comps, int decomp, bool io, bool ram) {
    size_t cpu = g_Compilers.size();

    // Safety clamp: Ensure total threads never exceeds CPU count
    int total = comps + decomp + (io ? 1 : 0) + (ram ? 1 : 0);
    if (total > cpu) {
        // Reduce compilers first to fit budget
        int overflow = total - (int)cpu;
        comps = std::max(0, comps - overflow);
    }

    for(size_t i=0; i<cpu; ++i) g_Compilers[i]->Start(i < (size_t)comps);
    for(size_t i=0; i<cpu; ++i) g_Decompress[i]->Start(i < (size_t)decomp);
    g_IO.Start(io); g_RAM.Start(ram);
    g_App.activeCompilers = comps; g_App.activeDecomp = decomp; g_App.ioActive = io; g_App.ramActive = ram;
}

void SmartSleep(int ms) { for (int i = 0; i < ms; i += 10) { if (!g_App.running) return; std::this_thread::sleep_for(10ms); } }

// 12-PHASE VARIABLE CYCLE
void RunDynamicPhase(int phaseIdx, int durationMs, int cpu) {
    auto start = std::chrono::steady_clock::now();
    std::mt19937 rng((unsigned)GetTick());

    // Common Strict Setter: Automatically balances to fit CPU count
    auto SetStrict = [&](int c, int d, bool io, bool ram) {
        int aux = (io?1:0) + (ram?1:0);
        int total = c + d + aux;
        if (total > cpu) {
            // Trim Decomp first, then Comp
            if (d > 0) {
                int over = total - cpu;
                int rem = std::min(d, over);
                d -= rem;
                total -= rem;
            }
            if (total > cpu) {
                c = std::max(0, c - (total - cpu));
            }
        }
        SetWork(c, d, io, ram);
    };

    while (g_App.running && g_App.mode == 2) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() >= durationMs) break;

        switch (phaseIdx) {
            case 0: // 1. All threads compiler
                SetStrict(cpu, 0, false, false);
                SmartSleep(100); break;

            case 1: // 2. Minus 4 compiler, 2 decomp + io/ram
                SetStrict(std::max(0, cpu - 4), 2, true, true);
                SmartSleep(100); break;

            case 2: // 3. Oscillate 0 <-> (Minus 4 compiler, 2 decomp + io/ram)
            {
                static bool t; t = !t;
                if (t) SetStrict(0, 0, false, false);
                else SetStrict(std::max(0, cpu - 4), 2, true, true);
                SmartSleep(500);
            }
            break;

            case 3: // 4. Only Decomp + IO/RAM (100% load)
                // Fill all cores with decomp + aux, NO compiler
                SetStrict(0, std::max(0, cpu - 2), true, true);
                SmartSleep(100); break;

            case 4: // 5. Oscillate 0 <-> (Decomp + IO/RAM)
            {
                static bool t; t = !t;
                if (t) SetStrict(0, 0, false, false);
                else SetStrict(0, std::max(0, cpu - 2), true, true);
                SmartSleep(500);
            }
            break;

            case 5: // 6. Random Compiler Only (Varying Util)
                SetStrict(rng() % (cpu + 1), 0, false, false);
                SmartSleep(500); break;

            case 6: // 7. Random Noise Only (Varying Util)
            {
                bool io = rng()%2; bool ram = rng()%2;
                int aux = (io?1:0) + (ram?1:0);
                int avail = std::max(0, cpu - aux);
                int d = (avail > 0) ? (rng() % (avail+1)) : 0;
                SetStrict(0, d, io, ram);
                SmartSleep(500);
            }
            break;

            case 7: // 8. Tiny Decomp (1 or 2 threads)
                SetStrict(0, 1 + (rng() % 2), false, false);
                SmartSleep(500); break;

            case 8: // 9. Tiny Compiler (1 or 2 threads)
                SetStrict(1 + (rng() % 2), 0, false, false);
                SmartSleep(500); break;

            case 9: // 10. Random Mix (Reasonable numbers)
            {
                bool io = rng()%2; bool ram = rng()%2;
                int aux = (io?1:0) + (ram?1:0);
                int avail = std::max(0, cpu - aux);
                // Random split of available
                int total_active = rng() % (avail + 1);
                int c = rng() % (total_active + 1);
                int d = total_active - c;
                SetStrict(c, d, io, ram);
                SmartSleep(500);
            }
            break;

            case 10: // 11. Mean Oscillation (PWM Stress)
                // 100% Load -> 0% Load. Random intervals.
                // 0% phase not too short (>300ms)
                SetStrict(cpu, 0, false, false); // Full blast
                SmartSleep(200 + (rng() % 800));

                if (g_App.running && g_App.mode == 2) {
                    SetStrict(0, 0, false, false); // Idle
                    SmartSleep(300 + (rng() % 500));
                }
                break;

            case 11: // 12. "Core/Uncore Toggle" (Meanest Load)
                // Alternating between AVX (Compiler) and Memory (Decomp)
                // This causes massive internal power plane switching
                SetStrict(cpu, 0, false, false); // All Math
                SmartSleep(100);
                if (g_App.running && g_App.mode == 2) {
                    SetStrict(0, cpu, false, false); // All Mem
                    SmartSleep(100);
                }
                break;
        }
    }
}

void DynamicLoop() {
    DisablePowerThrottling();
    int cpu = (int)g_Compilers.size();
    int pIdx = 0;
    while(g_App.running && g_App.mode == 2) {
        g_App.currentPhase = pIdx + 1;
        // 10 seconds per phase
        RunDynamicPhase(pIdx, 10000, cpu);
        pIdx = (pIdx + 1) % 12;
        if (pIdx == 0) g_App.loops++;
    }
}

void Watchdog() {
    DisablePowerThrottling();
    uint64_t lastCheck = GetTick(), minuteStartShaders = 0, minuteStartNodes = 0, minuteStartTime = 0, runStart = 0;
    bool warmingUp = false, lastRunning = false;
    while(!g_App.quit) {
        bool currentRunning = g_App.running;
        uint64_t now = GetTick();
        if (g_App.resetTimer.exchange(false)) { minuteStartShaders = 0; minuteStartNodes = 0; minuteStartTime = now; lastCheck = now; g_App.elapsed = 0; runStart = now; warmingUp = true; g_App.currentRate = 0; g_App.nodeRate = 0; if (currentRunning) { minuteStartShaders = g_App.shaders; minuteStartNodes = g_App.totalNodes; } }
        if (currentRunning && !lastRunning) g_App.resetTimer = true;
        lastRunning = currentRunning;
        if(currentRunning) {
            if (g_App.elapsed == 0 && runStart == 0) runStart = now;
            g_App.elapsed = (now - runStart) / 1000;
            if (warmingUp) { if (now - runStart > 2000) { warmingUp = false; minuteStartTime = now; minuteStartShaders = g_App.shaders; minuteStartNodes = g_App.totalNodes; lastCheck = now; } }
            else if (now - lastCheck >= 2000) {
                uint64_t currentShaders = g_App.shaders;
                uint64_t currentNodes = g_App.totalNodes;

                if (currentShaders >= minuteStartShaders) {
                    uint64_t timeInWindow = now - minuteStartTime;
                    if (timeInWindow > 100) {
                        g_App.currentRate = ((currentShaders - minuteStartShaders) * 60000) / timeInWindow;
                        g_App.nodeRate = ((currentNodes - minuteStartNodes) * 1000) / timeInWindow;
                    }
                    if (timeInWindow >= 60000) {
                        uint64_t finalRate = g_App.currentRate;
                        if (g_App.mode == 0) {
                            std::lock_guard<std::mutex> lk(g_App.metricsMtx); g_App.last3Rates.push_back(finalRate); if (g_App.last3Rates.size() > 3) g_App.last3Rates.pop_front();
                            uint64_t best = 0; for(uint64_t r : g_App.last3Rates) if(r > best) best = r; g_App.bestOf3 = best;
                        }
                        minuteStartTime = now; minuteStartShaders = currentShaders; minuteStartNodes = currentNodes;
                    }
                } else { minuteStartShaders = currentShaders; minuteStartNodes = currentNodes; minuteStartTime = now; }
                lastCheck = now;
            }
        } else runStart = 0;
        std::this_thread::sleep_for(500ms);
        if(g_MainWindow) InvalidateRect(g_MainWindow, nullptr, FALSE);
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if(m == WM_DESTROY) { g_App.quit = true; PostQuitMessage(0); return 0; }
    if(m == WM_PAINT) {
        PAINTSTRUCT ps; BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        HDC memDC = CreateCompatibleDC(ps.hdc); HBITMAP memBM = CreateCompatibleBitmap(ps.hdc, rc.right, rc.bottom); HBITMAP oldBM = (HBITMAP)SelectObject(memDC, memBM);
        HBRUSH bg = CreateSolidBrush(RGB(20,20,20)); FillRect(memDC, &rc, bg); DeleteObject(bg);
        SetBkMode(memDC, TRANSPARENT); SetTextColor(memDC, RGB(200,200,200));
        HFONT hFont = CreateFontW(-(int)(16 * g_Scale), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI"); HFONT oldFont = (HFONT)SelectObject(memDC, hFont);

        auto btn = [&](int id, const wchar_t* txt, int x, bool act) {
            RECT r{x, S(10), x+S(140), S(40)}; HBRUSH b = CreateSolidBrush(act ? RGB(60,100,160) : RGB(50,50,50)); FillRect(memDC, &r, b); DeleteObject(b);
            DrawTextW(memDC, txt, -1, &r, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        };

        bool run = g_App.running;
        btn(1, run ? L"STOP" : L"START", S(10), run); btn(2, L"Dynamic", S(160), g_App.mode==2); btn(3, L"Steady", S(310), g_App.mode==1); btn(4, L"Benchmark", S(460), g_App.mode==0); btn(5, L"Close", S(610), false);

        std::wstring part1 = L"Shader Stress v" + APP_VERSION + L"\nMode: " + g_App.sigStatus +
        L"\nJobs Done: " + FmtNum(g_App.shaders) +
        L"\n\n--- Performance ---" +
        L"\nThroughput: " + FmtNum(g_App.nodeRate / 1000) + L" KNodes/s" +
        L"\nRate (Jobs): " + FmtNum(g_App.currentRate) + L" /min" +
        L"\nTime: " + FmtTime(g_App.elapsed);

        if (g_App.mode == 2) {
            part1 += L"\nPhase: " + std::to_wstring(g_App.currentPhase) + L" / 12";
            part1 += L"\nLoop: " + std::to_wstring(g_App.loops);
        }

        std::wstring partError = L"Errors: " + FmtNum(g_App.errors);

        std::wstring part3 = L"\n\n--- Stress Status ---";
        part3 += L"\nSim Threads: " + FmtNum(g_App.activeCompilers);
        part3 += L"\nDecomp Threads: " + FmtNum(g_App.activeDecomp) + L" Active";
        part3 += L"\nRAM Thread: " + std::wstring(g_App.ramActive ? L"ACTIVE" : L"Idle");
        part3 += L"\nI/O Thread: " + std::wstring(g_App.ioActive ? L"ACTIVE" : L"Idle");

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
                if(g_DynThread.joinable()) g_DynThread.join();
                if (g_App.mode == 2) {
                    g_DynThread = std::thread(DynamicLoop);
                } else if (g_App.mode == 1) {
                    int cpu = (int)g_Compilers.size();
                    // Steady Mode: STRICT BUDGET
                    // Fixed: Decomp capped at 2. Aux threads (IO/RAM) are 2.
                    int aux = 2; // IO + RAM
                    int avail = std::max(0, cpu - aux);
                    int d = (avail >= 2) ? 2 : 0;
                    int c = std::max(0, avail - d);
                    SetWork(c, d, true, true);
                } else {
                    SetWork((int)g_Compilers.size(), 0, 0, 0);
                }
            };

            if (clickedStart) {
                g_App.running = !g_App.running;
                if(g_App.running) {
                    // FIX: Log which mode is starting
                    std::wstring m = (g_App.mode == 2 ? L"Dynamic" : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
                    g_App.Log(L"State changed: STARTED (Mode: " + m + L")");
                    g_App.shaders=0; g_App.elapsed=0; g_App.totalNodes=0; g_App.loops=0; g_App.currentPhase=0;
                    StartWorkload();
                } else {
                    g_App.Log(L"State changed: STOPPED");
                    SetWork(0,0,0,0);
                    if(g_DynThread.joinable()) g_DynThread.join();
                }
            } else if (newMode != -1 && newMode != g_App.mode) {
                g_App.mode = newMode;
                std::wstring modeName;
                if (newMode == 2) modeName = L"Dynamic";
                else if (newMode == 1) modeName = L"Steady";
                else modeName = L"Benchmark";
                g_App.Log(L"Mode changed to: " + modeName);

                if(g_App.running) StartWorkload();
            }
            g_App.resetTimer = true; InvalidateRect(h, nullptr, FALSE);
        }
    }
    return DefWindowProc(h, m, w, l);
}

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_Scale = GetDpiForSystem() / 96.0f;
    g_App.log.open("ShaderStress.log", std::ios::out | std::ios::trunc);
    g_App.log.imbue(std::locale(""));

    g_Cpu = GetCpuInfo();
    g_App.sigStatus = g_Cpu.name;
    g_App.Log(std::wstring(L"Started v") + APP_VERSION + L" (" + g_Cpu.name + L")");

    // CLI Parsing for Repro and License
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (lstrcmpiW(argv[i], L"--repro") == 0 && i + 2 < argc) {
                uint64_t s = _wcstoui64(argv[i+1], nullptr, 10);
                int c = _wtoi(argv[i+2]);
                RunReproMode(s, c); // Never returns
            }
            if (lstrcmpiW(argv[i], L"--license") == 0) {
                AllocConsole();
                freopen("CONOUT$", "w", stdout);
                freopen("CONIN$", "r", stdin);
                printf("%s\n", LICENSE_TEXT);
                printf("\nPress Enter to exit...");
                getchar();
                ExitProcess(0);
            }
        }
        LocalFree(argv);
    }

    int cpu = std::thread::hardware_concurrency();
    for(int i=0; i<cpu; ++i) g_Compilers.push_back(std::make_unique<Worker>());
    for(int i=0; i<cpu; ++i) g_Decompress.push_back(std::make_unique<Worker>());

    std::vector<std::thread> threads;
    for(int i=0; i<cpu; ++i) threads.emplace_back(CompilerThread, i);
    for(int i=0; i<cpu; ++i) threads.emplace_back(DecompressThread, i);
    threads.emplace_back(IOThread); threads.emplace_back(RAMThread);
    std::thread wd(Watchdog);

    WNDCLASSW wc{0, WndProc, 0, 0, inst, nullptr, LoadCursor(0, IDC_ARROW), nullptr, nullptr, L"SST"};
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCE(1)); RegisterClassW(&wc);
    int wW = S(800), wH = S(600);
    g_MainWindow = CreateWindowW(L"SST", L"Shader Stress", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE, (GetSystemMetrics(SM_CXSCREEN)-wW)/2, (GetSystemMetrics(SM_CYSCREEN)-wH)/2, wW, wH, 0, 0, inst, 0);
    BOOL useDark = TRUE; DwmSetWindowAttribute(g_MainWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));

    MSG msg; while(GetMessage(&msg, 0, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }

    // Shutdown Sequence
    g_App.quit = true;

    // 1. Stop Dynamic Manager
    if(g_DynThread.joinable()) g_DynThread.join();

    // 2. Signal ALL workers to stop
    for(auto& w : g_Compilers) { w->terminate = true; w->cv.notify_all(); }
    for(auto& w : g_Decompress) { w->terminate = true; w->cv.notify_all(); }
    g_IO.terminate = true; g_IO.cv.notify_all();
    g_RAM.terminate = true; g_RAM.cv.notify_all();

    // 3. Join all worker threads
    for(auto& t : threads) { if(t.joinable()) t.join(); }

    // 4. Join Watchdog
    if(wd.joinable()) wd.join();

    return 0;
}