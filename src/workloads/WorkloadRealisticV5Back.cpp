// WorkloadRealisticV5Back.cpp - Realistic V5 IR scheduling before instruction
// selection: instruction indexing (per-block instruction vectors in list
// order, like nir_index_instrs) and per-block list scheduling on a dependence
// DAG with a critical-path priority queue and an ACO-style motion window.
// Machine code: WorkloadRealisticV5Isel.cpp / Ra.cpp / Asm.cpp.
#include "workloads/WorkloadRealisticV5.h"
#include <array>
#include <utility>

namespace simv5 {
namespace {
constexpr uint32_t kSchedWindow = 24;
inline bool Scheduled(const Node &n) { return !(n.op & (kConstFlag | kDeadFlag)); }
inline uint32_t Latency(const Node &n) { return IsPhi(n) ? 0 : 1 + Info(OpOf(n)).latency; }

// Max-heap of 64-bit keys.
struct Heap {
  uint64_t *v;
  uint32_t n = 0;
  void Push(uint64_t key) {
    uint32_t k = n++;
    v[k] = key;
    while (k && v[(k - 1) / 2] < v[k]) {
      std::swap(v[(k - 1) / 2], v[k]);
      k = (k - 1) / 2;
    }
  }
  uint64_t Pop() {
    const uint64_t top = v[0];
    v[0] = v[--n];
    for (uint32_t k = 0;;) {
      uint32_t c = 2 * k + 1;
      if (c >= n) break;
      if (c + 1 < n && v[c + 1] > v[c]) ++c;
      if (v[k] >= v[c]) break;
      std::swap(v[k], v[c]);
      k = c;
    }
    return top;
  }
};

} // namespace

// Per-block instruction vectors in list order (phis first); Node::pos is the
// position. Later passes address instructions by position, not by node slot.
void Linearize(Fn &f, Arena &ar) {
  f.seq = ar.Take<uint32_t>(f.n);
  f.seqStart = ar.Take<uint32_t>((size_t)f.nblocks + 1);
  uint32_t k = 0;
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    f.seqStart[b] = k;
    for (uint32_t i = f.blocks[b].head; i != kNone && k < f.n; i = f.nodes[i].next) {
      f.nodes[i].pos = k;
      f.seq[k++] = i;
    }
  }
  f.seqStart[f.nblocks] = k;
  f.nseq = k;
}

// Per-block list scheduling: phis stay first; other instructions follow a
// ready list ordered by critical-path height (then list order); side effects
// keep their relative order.
void Schedule(Fn &f, Arena &ar) {
  const uint32_t ns = f.nseq;
  f.order = ar.Take<uint32_t>(ns ? ns : 1);
  f.blockStart = ar.Take<uint32_t>((size_t)f.nblocks + 1);
  uint32_t *npred = ar.Take<uint32_t>(ns + 1); // by position
  uint32_t *height = ar.Take<uint32_t>(ns + 1);
  uint32_t *chain = ar.Take<uint32_t>(ns + 1);
  Heap ready{ar.Take<uint64_t>(ns + 1)};
  Heap deferred{ar.Take<uint64_t>(ns + 1)}; // ready but outside the window: min position on top
  uint32_t out = 0;
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    const uint32_t end = f.seqStart[b + 1];
    f.blockStart[b] = out;
    uint32_t first = f.seqStart[b];
    for (; first < end && IsPhi(f.nodes[f.seq[first]]); ++first) f.order[out++] = f.seq[first];
    auto local = [&](uint32_t v) { // position of an in-block operand, else kNone
      if (v == kNone || !Scheduled(f.nodes[v]) || IsPhi(f.nodes[v])) return kNone;
      const uint32_t p = f.nodes[v].pos;
      return p >= first && p < end ? p : kNone;
    };
    uint32_t lastSide = kNone;
    for (uint32_t p = first; p < end; ++p) {
      const Node &n = f.nodes[f.seq[p]];
      chain[p] = kNone;
      npred[p] = (local(n.a) != kNone) + (local(n.b) != kNone) + (local(n.c) != kNone);
      if (IsStore(n)) {
        if (lastSide != kNone) {
          chain[lastSide] = p;
          npred[p]++;
        }
        lastSide = p;
      }
    }
    // ACO-style bounded motion: a ready instruction is eligible only within
    // kSchedWindow of the oldest unscheduled one (limits register pressure).
    uint32_t low = first;
    auto key = [&](uint32_t p) { return ((uint64_t)height[p] << 32) | (0xFFFFFFFFu - p); };
    auto release = [&](uint32_t p) {
      if (p <= low + kSchedWindow) ready.Push(key(p));
      else deferred.Push(0xFFFFFFFFu - p);
    };
    for (uint32_t p = end; p-- > first;) {
      const Node &n = f.nodes[f.seq[p]];
      const uint32_t lat = Latency(n);
      uint32_t h = lat;
      for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
        const uint32_t up = local(UseUser(u));
        if (up != kNone && up > p) h = std::max(h, lat + height[up]);
      }
      if (chain[p] != kNone) h = std::max(h, 1 + height[chain[p]]);
      height[p] = h;
      if (npred[p] == 0) release(p);
    }
    uint32_t expect = first;
    while (ready.n || deferred.n) {
      if (!ready.n) ready.Push(key(0xFFFFFFFFu - (uint32_t)deferred.Pop()));
      const uint32_t p = 0xFFFFFFFFu - (uint32_t)ready.Pop();
      if (p != expect) f.st.schedMoved++;
      ++expect;
      f.order[out++] = f.seq[p];
      npred[p] = kNone; // scheduled
      while (low < end && npred[low] == kNone) ++low;
      while (deferred.n && 0xFFFFFFFFu - (uint32_t)deferred.v[0] <= low + kSchedWindow)
        ready.Push(key(0xFFFFFFFFu - (uint32_t)deferred.Pop()));
      const Node &n = f.nodes[f.seq[p]];
      for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
        const uint32_t up = local(UseUser(u));
        if (up != kNone && up > p && npred[up] != kNone && --npred[up] == 0) release(up);
      }
      if (chain[p] != kNone && --npred[chain[p]] == 0) release(chain[p]);
    }
  }
  f.blockStart[f.nblocks] = out;
  f.norder = out;
  // Relink each block's instruction list in schedule order (moveBefore).
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    const uint32_t s = f.blockStart[b], e = f.blockStart[b + 1];
    f.blocks[b].head = s < e ? f.order[s] : kNone;
    for (uint32_t k = s; k < e; ++k) {
      Node &n = f.nodes[f.order[k]];
      n.pos = k;
      n.prev = k > s ? f.order[k - 1] : kNone;
      n.next = k + 1 < e ? f.order[k + 1] : kNone;
    }
  }
}

} // namespace simv5
