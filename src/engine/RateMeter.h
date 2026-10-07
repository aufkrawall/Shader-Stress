// RateMeter.h - Sliding-window job rate for the live display (GUI / CLI).
//
// Benchmark and dynamic jobs are heavy-tailed like real shader compiles (1/16
// up to ~10x, 1/256 up to ~40x a typical job; ComplexityForPair), so the jobs
// finished in one 1 s window swing with how many workers currently hold a
// large job. The meter averages over a longer window of (tick, jobs) samples
// taken at the watchdog cadence. Scores are unaffected: benchmark minutes
// count their own jobs.
#pragma once
#include <cstddef>
#include <cstdint>

class RateMeter {
public:
  static constexpr size_t kCap = 128; // samples: window / 250 ms cadence + slack

  void Reset(uint64_t tick, uint64_t jobs) {
    head_ = 0;
    n_ = 0;
    Push(tick, jobs);
  }
  // Records a sample and returns jobs/s over the last `windowMs` (the oldest
  // kept sample is the newest one at least `windowMs` old, or the Reset
  // sample while less time has passed). 0 until time has advanced.
  uint64_t Sample(uint64_t tick, uint64_t jobs, uint64_t windowMs) {
    Push(tick, jobs);
    while (n_ > 1 && tick - At(1).tick >= windowMs) Pop(); // At(1) still spans the window
    const Point &o = At(0);
    const uint64_t dt = tick - o.tick;
    return dt ? (jobs - o.jobs) * 1000 / dt : 0;
  }
  uint64_t SpanMs() const { return n_ ? At(n_ - 1).tick - At(0).tick : 0; }

private:
  struct Point {
    uint64_t tick, jobs;
  };
  const Point &At(size_t k) const { return ring_[(head_ + k) % kCap]; }
  void Pop() {
    head_ = (head_ + 1) % kCap;
    --n_;
  }
  void Push(uint64_t tick, uint64_t jobs) {
    if (n_ == kCap) Pop(); // window longer than the ring: keep the newest kCap
    ring_[(head_ + n_) % kCap] = {tick, jobs};
    ++n_;
  }
  Point ring_[kCap] = {};
  size_t head_ = 0, n_ = 0;
};

// Display window per mode: benchmark readings settle over 10 s (minutes are
// scored separately); other modes follow load changes within 2 s.
constexpr uint64_t RateWindowMs(bool benchmark) { return benchmark ? 10000 : 2000; }
