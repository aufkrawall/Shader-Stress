// IoStress.cpp - Verified storage streamer: writes a pattern file once per run
// (incrementally, one chunk per service step), then keeps uncached 256 KiB
// random reads in flight and verifies every word of each completed read. It is
// driven by the pinned stream worker between its decompression passes, so the
// worker's logical CPU stays busy while the device works.
#include "engine/AuxStress.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"

#if !defined(PLATFORM_WINDOWS)
#include <fcntl.h>
#include <sys/stat.h>
#endif

namespace {
inline uint64_t IoWord(uint64_t block, size_t word, uint64_t seed) {
  return PatternWord(block * (IO_BLOCK_SIZE / 8) + word, seed);
}

// Minimal cross-platform file wrapper.
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

bool OpenForCreate(const std::wstring &path, IoFile &f) {
#ifdef PLATFORM_WINDOWS
  f.h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
#else
  f.fd = open(ToNarrow(path).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
  return f.Valid();
}

bool WriteChunk(IoFile &f, const void *p, size_t len) {
#ifdef PLATFORM_WINDOWS
  DWORD written = 0;
  return WriteFile(f.h, p, (DWORD)len, &written, nullptr) && written == len;
#else
  return write(f.fd, p, len) == (ssize_t)len;
#endif
}

void FlushFile(IoFile &f) {
#ifdef PLATFORM_WINDOWS
  FlushFileBuffers(f.h);
#else
  fsync(f.fd);
#endif
}

bool OpenUncached(const std::wstring &path, IoFile &f, std::wstring &mode) {
#ifdef PLATFORM_WINDOWS
  f.h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED | FILE_FLAG_RANDOM_ACCESS,
                    nullptr);
  mode = L"unbuffered overlapped";
  return f.Valid();
#else
  std::string p = ToNarrow(path);
#ifdef PLATFORM_LINUX
  f.fd = open(p.c_str(), O_RDONLY | O_DIRECT);
  mode = L"O_DIRECT, synchronous";
  if (f.fd < 0) {
    // tmpfs and some filesystems reject O_DIRECT; fall back to cached reads
    // with explicit page-cache eviction after each read.
    f.fd = open(p.c_str(), O_RDONLY);
    mode = L"cached+fadvise(DONTNEED), synchronous";
  }
#else
  f.fd = open(p.c_str(), O_RDONLY);
  if (f.fd >= 0) fcntl(f.fd, F_NOCACHE, 1);
  mode = L"F_NOCACHE, synchronous";
#endif
  return f.Valid();
#endif
}

#if !defined(PLATFORM_WINDOWS)
bool ReadAt(IoFile &f, void *buf, uint64_t offset, size_t len) {
  ssize_t got = pread(f.fd, buf, len, (off_t)offset);
#ifdef PLATFORM_LINUX
  posix_fadvise(f.fd, (off_t)offset, (off_t)len, POSIX_FADV_DONTNEED);
#endif
  return got == (ssize_t)len;
}
#endif

void DeleteTempFile(const std::wstring &path) {
#ifdef PLATFORM_WINDOWS
  DeleteFileW(path.c_str());
#else
  unlink(ToNarrow(path).c_str());
#endif
}

constexpr int kMaxReadFailures = 8; // consecutive failures before giving up
} // namespace

void FillIoChunk(uint64_t *p, uint64_t firstBlock, size_t blocks, uint64_t seed) {
  for (size_t b = 0; b < blocks; ++b)
    for (size_t w = 0; w < IO_BLOCK_SIZE / 8; ++w)
      p[b * (IO_BLOCK_SIZE / 8) + w] = IoWord(firstBlock + b, w, seed);
}

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

std::wstring IoTempFilePath(const wchar_t *tag) {
#ifdef PLATFORM_WINDOWS
  wchar_t dir[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, dir);
  std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(dir) : std::wstring(L".\\");
  return base + L"ShaderStress_" + tag + L"_" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
#else
  const char *env = getenv("TMPDIR");
  std::string dir = (env && *env) ? env : (access("/var/tmp", W_OK) == 0 ? "/var/tmp" : "/tmp");
  std::string p = dir + "/ShaderStress_" + ToNarrow(tag) + "_" + std::to_string((long)getpid()) +
                  ".tmp";
  return ToWide(p);
#endif
}

// ---------------------------------------------------------------------------
// IoStreamer
// ---------------------------------------------------------------------------
struct IoStreamer::Impl {
  enum class Phase { Idle, Create, Read, Disabled };
  struct Slot {
    ScopedMem buf{0};
    uint64_t firstBlock = 0;
    bool pending = false;
    uint64_t issueSeq = 0;         // issue order: blocking waits take the oldest read
#ifdef PLATFORM_WINDOWS
    OVERLAPPED ov{};
    HANDLE ev = nullptr;
    bool issueFailed = false;
#endif
  };

  Phase phase = Phase::Idle;
  std::wstring path;
  uint64_t bytes = 0, seed = 0;
  int depth = 1;
  // Create phase
  IoFile wf;
  uint64_t written = 0;
  std::chrono::steady_clock::time_point createStart;
  // Read phase
  IoFile rf;
  std::unique_ptr<Slot[]> slots; // fixed addresses: OVERLAPPED must not move
  int slotCount = 0;
  uint64_t issued = 0;
  uint64_t rng = 1, hash = 0;
  uint64_t blocksRange = 0;      // valid first-block range for a read
  int consecutiveFailures = 0;
  IoStreamStats stats;
  uint64_t lastLogTick = 0, lastLogReads = 0;
  bool fileExists = false;

  void Disable(const std::wstring &why) {
    g_App.Log(L"I/O streamer: " + why + L", I/O disabled for this run (worker keeps decompressing)");
    CloseAll();
    phase = Phase::Disabled;
    stats.disabled = true;
    stats.ready = false;
    AuxStatusSetIo(false, 0);
  }

  bool StartReads() {
    std::wstring mode;
    if (!OpenUncached(path, rf, mode)) {
      Disable(L"could not reopen " + path + L" uncached");
      return false;
    }
#ifdef PLATFORM_WINDOWS
    slotCount = depth;
#else
    slotCount = 1;
#endif
    slots = std::make_unique<Slot[]>((size_t)slotCount);
    for (int i = 0; i < slotCount; ++i) {
      slots[i].buf = ScopedMem(IO_CHUNK_SIZE); // page aligned (required for uncached I/O)
      if (!slots[i].buf) {
        Disable(L"read buffer allocation failed");
        return false;
      }
#ifdef PLATFORM_WINDOWS
      slots[i].ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (!slots[i].ev) {
        Disable(L"CreateEvent failed (" + std::to_wstring(GetLastError()) + L")");
        return false;
      }
#endif
    }
    blocksRange = bytes / IO_BLOCK_SIZE - IO_CHUNK_SIZE / IO_BLOCK_SIZE + 1;
    rng = seed | 1u;
    phase = Phase::Read;
    stats.ready = true;
    const double sec =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - createStart).count();
    g_App.Log(L"I/O streamer: " + FmtBytes(bytes) + L" pattern file written (" +
              Fmt("%.0f MiB/s", sec > 0 ? (double)bytes / 1048576.0 / sec : 0.0) +
              L", interleaved with decompression), reads: " + mode + L", queue depth " +
              std::to_wstring(slotCount) + L" [" + path + L"]");
    AuxStatusSetIo(true, 0);
    lastLogTick = GetTick();
#ifdef PLATFORM_WINDOWS
    for (int i = 0; i < slotCount; ++i) Issue(slots[i]);
#endif
    return true;
  }

  // Create phase: one chunk per call.
  void CreateStep() {
    if (!wf.Valid()) {
      if (!OpenForCreate(path, wf)) {
        Disable(L"could not create " + path);
        return;
      }
      fileExists = true;
      SetCrashCleanupFile(path);
      createStart = std::chrono::steady_clock::now();
      written = 0;
      slots = std::make_unique<Slot[]>(1);
      slots[0].buf = ScopedMem(IO_CHUNK_SIZE);
      if (!slots[0].buf) {
        Disable(L"write buffer allocation failed");
        return;
      }
    }
    uint64_t *p = slots[0].buf.As<uint64_t>();
    FillIoChunk(p, written / IO_BLOCK_SIZE, IO_CHUNK_SIZE / IO_BLOCK_SIZE, seed);
    if (!WriteChunk(wf, p, IO_CHUNK_SIZE)) {
      Disable(L"write failed at offset " + FmtHex64(written));
      return;
    }
    written += IO_CHUNK_SIZE;
    if (written >= bytes) {
      FlushFile(wf); // reads must come from the device, not dirty cache
      wf.Close();
      slots.reset();
      StartReads();
    }
  }

  uint64_t NextFirstBlock() {
    rng = Mix64(rng + GOLDEN_RATIO);
    return rng % blocksRange;
  }

#ifdef PLATFORM_WINDOWS
  void Issue(Slot &s) {
    s.firstBlock = NextFirstBlock();
    const uint64_t off = s.firstBlock * IO_BLOCK_SIZE;
    HANDLE ev = s.ev;
    s.ov = OVERLAPPED{};
    s.ov.hEvent = ev;
    s.ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
    s.ov.OffsetHigh = (DWORD)(off >> 32);
    s.pending = true;
    s.issueSeq = issued++;
    s.issueFailed = false;
    if (!ReadFile(rf.h, s.buf.ptr, (DWORD)IO_CHUNK_SIZE, nullptr, &s.ov) &&
        GetLastError() != ERROR_IO_PENDING)
      s.issueFailed = true; // reported when harvested
  }

  // Returns true when the slot completed (and was processed + re-issued).
  bool Harvest(Slot &s, bool wait) {
    if (!s.pending) return false;
    if (!s.issueFailed && !wait && !HasOverlappedIoCompleted(&s.ov)) return false;
    DWORD got = 0;
    const bool ok = !s.issueFailed && GetOverlappedResult(rf.h, &s.ov, &got, wait ? TRUE : FALSE) &&
                    got == IO_CHUNK_SIZE;
    s.pending = false;
    Process(s, ok);
    if (phase == Phase::Read) Issue(s);
    return true;
  }
#endif

  void Process(Slot &s, bool ok) {
    const uint64_t off = s.firstBlock * IO_BLOCK_SIZE;
    if (!ok) {
      ++stats.readFailures;
      ReportHardwareError(ErrorSource::Io, -1, L"read failed at offset " + FmtHex64(off));
      if (++consecutiveFailures >= kMaxReadFailures)
        Disable(std::to_wstring(kMaxReadFailures) + L" consecutive read failures");
      return;
    }
    consecutiveFailures = 0;
    PatternError first;
    size_t bad = VerifyIoChunk(s.buf.As<uint64_t>(), s.firstBlock, IO_CHUNK_SIZE / IO_BLOCK_SIZE,
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
    ++stats.reads;
    if ((stats.reads & 63) == 0) AuxStatusSetIo(true, 64);
  }

  void ReadStep(bool block) {
    ++stats.serviceCalls;
#ifdef PLATFORM_WINDOWS
    int done = 0;
    for (int i = 0; i < slotCount && phase == Phase::Read; ++i)
      if (Harvest(slots[i], false)) ++done;
    if (phase != Phase::Read) return; // disabled while processing
    if (done == slotCount) ++stats.drainedCalls;
    if (done == 0) {
      ++stats.pendingCalls;
      if (block) { // no CPU filler: wait for the oldest read in flight
        int oldest = 0;
        for (int i = 1; i < slotCount; ++i)
          if (slots[i].issueSeq < slots[oldest].issueSeq) oldest = i;
        Harvest(slots[oldest], true);
      }
    }
#else
    (void)block;
    Slot &s = slots[0];
    s.firstBlock = NextFirstBlock();
    Process(s, ReadAt(rf, s.buf.ptr, s.firstBlock * IO_BLOCK_SIZE, IO_CHUNK_SIZE));
#endif
    if (phase == Phase::Read) MaybeLog();
  }

  void MaybeLog() {
    const uint64_t now = GetTick();
    if (now - lastLogTick < 30000) return;
    const double sec = (double)(now - lastLogTick) / 1000.0;
    const double mib = (double)(stats.reads - lastLogReads) * (IO_CHUNK_SIZE / 1048576.0);
    g_App.Log(Fmt("I/O streamer: %llu verified reads, %.0f MiB/s (last %.0f s), service calls "
                  "%llu: all reads pending %.0f%%, queue drained %.0f%%, read failures %llu",
                  (unsigned long long)stats.reads, sec > 0 ? mib / sec : 0.0, sec,
                  (unsigned long long)stats.serviceCalls,
                  stats.serviceCalls ? 100.0 * (double)stats.pendingCalls / (double)stats.serviceCalls : 0.0,
                  stats.serviceCalls ? 100.0 * (double)stats.drainedCalls / (double)stats.serviceCalls : 0.0,
                  (unsigned long long)stats.readFailures));
    lastLogTick = now;
    lastLogReads = stats.reads;
  }

  // Cancels and drains in-flight reads before any buffer or handle goes away.
  void CloseAll() {
#ifdef PLATFORM_WINDOWS
    if (rf.Valid() && slots) {
      CancelIoEx(rf.h, nullptr);
      for (int i = 0; i < slotCount; ++i) {
        Slot &s = slots[i];
        if (s.pending && !s.issueFailed) {
          DWORD got = 0;
          GetOverlappedResult(rf.h, &s.ov, &got, TRUE); // ERROR_OPERATION_ABORTED expected
        }
        s.pending = false;
      }
    }
    if (slots)
      for (int i = 0; i < slotCount; ++i)
        if (slots[i].ev) {
          CloseHandle(slots[i].ev);
          slots[i].ev = nullptr;
        }
#endif
    rf.Close();
    wf.Close();
    slots.reset();
    slotCount = 0;
    if (fileExists) {
      DeleteTempFile(path);
      SetCrashCleanupFile(L"");
      fileExists = false;
    }
  }
};

IoStreamer::IoStreamer() : impl_(std::make_unique<Impl>()) {}
IoStreamer::~IoStreamer() { Shutdown(true); }

void IoStreamer::Configure(const std::wstring &path, uint64_t bytes, uint64_t seed,
                           int queueDepth) {
  Shutdown(true);
  impl_ = std::make_unique<Impl>(); // fresh state (handles/buffers already released)
  Impl &m = *impl_;
  m.path = path;
  m.bytes = std::max<uint64_t>(IO_CHUNK_SIZE, bytes) & ~(uint64_t)(IO_CHUNK_SIZE - 1);
  m.seed = seed;
  m.depth = std::clamp(queueDepth, 1, 64);
  m.phase = Impl::Phase::Create;
}

bool IoStreamer::Configured() const { return impl_->phase != Impl::Phase::Idle; }

void IoStreamer::Service(bool block) {
  Impl &m = *impl_;
  switch (m.phase) {
  case Impl::Phase::Create: m.CreateStep(); break;
  case Impl::Phase::Read: m.ReadStep(block); break;
  default: break;
  }
}

void IoStreamer::Shutdown(bool quiet) {
  Impl &m = *impl_;
  if (m.phase == Impl::Phase::Idle) return;
  const bool wasActive = m.phase != Impl::Phase::Disabled;
  m.CloseAll();
  if (!quiet && wasActive) {
    g_App.Log(Fmt("I/O streamer: stopped after %llu verified reads (service calls %llu, all "
                  "pending %llu, drained %llu, read failures %llu)",
                  (unsigned long long)m.stats.reads, (unsigned long long)m.stats.serviceCalls,
                  (unsigned long long)m.stats.pendingCalls,
                  (unsigned long long)m.stats.drainedCalls,
                  (unsigned long long)m.stats.readFailures));
    AuxStatusSetIo(false, 0);
  }
  m.phase = Impl::Phase::Idle;
  m.stats.ready = false;
}

IoStreamStats IoStreamer::Stats() const { return impl_->stats; }

std::mutex &IoStreamMutex() {
  static std::mutex m;
  return m;
}

IoStreamer &GlobalIoStreamer() {
  static IoStreamer s;
  return s;
}

bool ReleaseIoStream() {
  std::lock_guard<std::mutex> lk(IoStreamMutex());
  IoStreamer &s = GlobalIoStreamer();
  if (!s.Configured()) return false;
  s.Shutdown(false);
  return true;
}
