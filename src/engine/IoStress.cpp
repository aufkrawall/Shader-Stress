// IoStress.cpp - Verified storage tester: writes a pattern file once per run,
// then performs random uncached 256 KiB reads and verifies every word.
#include "engine/AuxStress.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"

#if !defined(PLATFORM_WINDOWS)
#include <fcntl.h>
#include <sys/stat.h>
#endif

namespace {
// Every 4 KiB block carries words derived from its block index, so stale,
// misdirected or corrupted reads are all detected.
inline uint64_t IoWord(uint64_t block, size_t word, uint64_t seed) {
  return PatternWord(block * (IO_BLOCK_SIZE / 8) + word, seed);
}

void FillIoChunk(uint64_t *p, uint64_t firstBlock, size_t blocks, uint64_t seed) {
  for (size_t b = 0; b < blocks; ++b)
    for (size_t w = 0; w < IO_BLOCK_SIZE / 8; ++w)
      p[b * (IO_BLOCK_SIZE / 8) + w] = IoWord(firstBlock + b, w, seed);
}

// Verifies a chunk and hashes it (CPU work on the I/O core). Returns errors.
size_t VerifyIoChunk(const uint64_t *p, uint64_t firstBlock, size_t blocks, uint64_t seed,
                     uint64_t &hash, PatternError &first) {
  size_t bad = 0;
  uint64_t h = hash;
  for (size_t b = 0; b < blocks; ++b) {
    for (size_t w = 0; w < IO_BLOCK_SIZE / 8; ++w) {
      uint64_t got = p[b * (IO_BLOCK_SIZE / 8) + w];
      uint64_t exp = IoWord(firstBlock + b, w, seed);
      if (got != exp) [[unlikely]] {
        if (bad == 0)
          first = PatternError{(firstBlock + b) * IO_BLOCK_SIZE + w * 8, exp, got};
        ++bad;
      }
      h = (h ^ got) * 0x9E3779B97F4A7C15ull;
    }
  }
  hash = h;
  return bad;
}

std::wstring TempFilePath() {
#ifdef PLATFORM_WINDOWS
  wchar_t dir[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, dir);
  std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(dir) : std::wstring(L".\\");
  return base + L"ShaderStress_io_" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
#else
  const char *env = getenv("TMPDIR");
  std::string dir = (env && *env) ? env : (access("/var/tmp", W_OK) == 0 ? "/var/tmp" : "/tmp");
  std::string p = dir + "/ShaderStress_io_" + std::to_string((long)getpid()) + ".tmp";
  return ToWide(p);
#endif
}

// Minimal cross-platform file wrapper for the tester.
struct IoFile {
#ifdef PLATFORM_WINDOWS
  HANDLE h = INVALID_HANDLE_VALUE;
  bool Valid() const { return h != INVALID_HANDLE_VALUE; }
  void Close() {
    if (Valid()) CloseHandle(h);
    h = INVALID_HANDLE_VALUE;
  }
#else
  int fd = -1;
  bool Valid() const { return fd >= 0; }
  void Close() {
    if (Valid()) close(fd);
    fd = -1;
  }
#endif
  ~IoFile() { Close(); }
};

bool CreatePatternFile(const std::wstring &path, uint64_t bytes, uint64_t seed, void *chunkBuf) {
  constexpr size_t kWriteChunk = IO_CHUNK_SIZE;
  IoFile f;
#ifdef PLATFORM_WINDOWS
  f.h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
#else
  f.fd = open(ToNarrow(path).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
  if (!f.Valid()) return false;
  uint64_t *p = static_cast<uint64_t *>(chunkBuf);
  for (uint64_t off = 0; off < bytes; off += kWriteChunk) {
    if (AuxTerminating()) return false;
    FillIoChunk(p, off / IO_BLOCK_SIZE, kWriteChunk / IO_BLOCK_SIZE, seed);
#ifdef PLATFORM_WINDOWS
    DWORD written = 0;
    if (!WriteFile(f.h, p, (DWORD)kWriteChunk, &written, nullptr) || written != kWriteChunk)
      return false;
#else
    if (write(f.fd, p, kWriteChunk) != (ssize_t)kWriteChunk) return false;
#endif
  }
#ifdef PLATFORM_WINDOWS
  FlushFileBuffers(f.h);
#else
  fsync(f.fd);
#endif
  return true;
}

bool OpenUncached(const std::wstring &path, IoFile &f, std::wstring &mode) {
#ifdef PLATFORM_WINDOWS
  f.h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, nullptr);
  mode = L"unbuffered";
  return f.Valid();
#else
  std::string p = ToNarrow(path);
#ifdef PLATFORM_LINUX
  f.fd = open(p.c_str(), O_RDONLY | O_DIRECT);
  mode = L"O_DIRECT";
  if (f.fd < 0) {
    // tmpfs and some filesystems reject O_DIRECT; fall back to cached reads
    // with explicit page-cache eviction after each read.
    f.fd = open(p.c_str(), O_RDONLY);
    mode = L"cached+fadvise(DONTNEED)";
  }
#else
  f.fd = open(p.c_str(), O_RDONLY);
  if (f.fd >= 0) fcntl(f.fd, F_NOCACHE, 1);
  mode = L"F_NOCACHE";
#endif
  return f.Valid();
#endif
}

bool ReadAt(IoFile &f, void *buf, uint64_t offset, size_t len) {
#ifdef PLATFORM_WINDOWS
  LARGE_INTEGER pos;
  pos.QuadPart = (LONGLONG)offset;
  if (!SetFilePointerEx(f.h, pos, nullptr, FILE_BEGIN)) return false;
  DWORD got = 0;
  return ReadFile(f.h, buf, (DWORD)len, &got, nullptr) && got == len;
#else
  ssize_t got = pread(f.fd, buf, len, (off_t)offset);
#ifdef PLATFORM_LINUX
  posix_fadvise(f.fd, (off_t)offset, (off_t)len, POSIX_FADV_DONTNEED);
#endif
  return got == (ssize_t)len;
#endif
}

void DeleteTempFile(const std::wstring &path) {
#ifdef PLATFORM_WINDOWS
  DeleteFileW(path.c_str());
#else
  unlink(ToNarrow(path).c_str());
#endif
}
} // namespace

void IoTesterThread() {
  DisablePowerThrottling();
  SetFpuFlushMode();
  CurrentJob().workload = JOB_WORKLOAD_IO;
  CurrentJob().worker = -200;

  if (!AuxWaitActive(true)) return;

  const uint64_t fileBytes =
      std::max<uint64_t>(16ull << 20, g_RunOpts.ioBytes) & ~(uint64_t)(IO_CHUNK_SIZE - 1);
  const std::wstring path = TempFilePath();
  const uint64_t seed = Mix64(GetTick() ^ 0x494F5445ull);
  ScopedMem buf(IO_CHUNK_SIZE); // page aligned (required for uncached I/O)
  if (!buf) {
    g_App.Log(L"I/O tester: buffer allocation failed, tester disabled for this run");
    return;
  }

  auto t0 = std::chrono::steady_clock::now();
  SetCrashCleanupFile(path);
  if (!CreatePatternFile(path, fileBytes, seed, buf.ptr)) {
    g_App.Log(L"I/O tester: could not create " + path +
              (AuxTerminating() ? L" (stopped)" : L" (write failed), tester disabled"));
    DeleteTempFile(path);
    SetCrashCleanupFile(L"");
    return;
  }
  double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  IoFile f;
  std::wstring mode;
  if (!OpenUncached(path, f, mode)) {
    g_App.Log(L"I/O tester: could not reopen " + path + L", tester disabled");
    DeleteTempFile(path);
    SetCrashCleanupFile(L"");
    return;
  }
  g_App.Log(L"I/O tester: " + FmtBytes(fileBytes) + L" pattern file written (" +
            Fmt("%.0f MiB/s", sec > 0 ? (double)fileBytes / 1048576.0 / sec : 0.0) +
            L"), reads: " + mode + L" [" + path + L"]");
  AuxStatusSetIo(true, 0);

  uint64_t rng = seed | 1u;
  uint64_t reads = 0, hash = 0;
  int readFailures = 0;
  const uint64_t chunks = fileBytes / IO_BLOCK_SIZE - IO_CHUNK_SIZE / IO_BLOCK_SIZE;
  while (AuxWaitActive(true)) {
    rng = Mix64(rng + GOLDEN_RATIO);
    uint64_t firstBlock = rng % (chunks + 1);
    if (!ReadAt(f, buf.ptr, firstBlock * IO_BLOCK_SIZE, IO_CHUNK_SIZE)) {
      ReportHardwareError(ErrorSource::Io, -1,
                          L"read failed at offset " + FmtHex64(firstBlock * IO_BLOCK_SIZE));
      if (++readFailures >= 8) {
        g_App.Log(L"I/O tester: 8 consecutive read failures, tester disabled for this run");
        break;
      }
      continue;
    }
    readFailures = 0;
    PatternError first;
    size_t bad = VerifyIoChunk(buf.As<uint64_t>(), firstBlock, IO_CHUNK_SIZE / IO_BLOCK_SIZE,
                               seed, hash, first);
    if (bad) {
      ReportHardwareError(ErrorSource::Io, -1,
                          L"data mismatch at file offset " + FmtHex64(first.index) +
                              L": expected " + FmtHex64(first.expected) + L" got " +
                              FmtHex64(first.actual) + L" (" + std::to_wstring(bad) +
                              L" bad words in read)");
      AddHardwareErrors(ErrorSource::Io, -1, bad - 1);
    }
    CountIoVerified(IO_CHUNK_SIZE);
    ++reads;
    if ((reads & 63) == 0) AuxStatusSetIo(true, 64);
  }
  volatile uint64_t sink = hash;
  (void)sink;
  f.Close();
  DeleteTempFile(path);
  SetCrashCleanupFile(L"");
  AuxStatusSetIo(false, 0);
  g_App.Log(L"I/O tester: stopped after " + std::to_wstring(reads) + L" verified reads");
}
