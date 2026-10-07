// WorkloadRealisticV5Back.cpp - Realistic V5 back end: dense-bitset block
// liveness (NIR-style iterative dataflow), per-block list scheduling on a
// dependence DAG with a critical-path priority queue, live ranges, linear-scan
// register allocation and per-opcode encoders with a hash of the binary.
#include "workloads/WorkloadRealisticV5.h"
#include <array>
#include <utility>

namespace simv5 {
namespace {
inline bool NeedsLive(const Node &n) {
  return !(n.op & (kConstFlag | kDeadFlag)) && (n.op & (kPhiFlag | kInputFlag) || !IsStoreOp(n.op & kOpMask));
}
constexpr uint32_t kSchedWindow = 24;
inline bool Scheduled(const Node &n) { return !(n.op & (kConstFlag | kDeadFlag)); }
inline uint32_t Latency(const Node &n) {
  if (IsInput(n)) return 24; // memory
  const uint32_t op = n.op & kOpMask;
  return 1 + (Family(op) == 5 ? 8 : Family(op) == 1 ? 3 : 0) + (op >= 0x80 ? 4 : 0);
}
inline void SetBit(uint64_t *s, uint32_t k) { s[k >> 6] |= 1ull << (k & 63); }
inline void ClearBit(uint64_t *s, uint32_t k) { s[k >> 6] &= ~(1ull << (k & 63)); }

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

// --- Emission: one distinct encoder per opcode ------------------------------
inline uint8_t *PutVar(uint8_t *p, uint64_t v) {
  while (v >= 0x80) {
    *p++ = (uint8_t)(v | 0x80);
    v >>= 7;
  }
  *p++ = (uint8_t)v;
  return p;
}
inline uint8_t *PutLE(uint8_t *p, uint64_t v, int bytes) {
  for (int k = 0; k < bytes; ++k) *p++ = (uint8_t)(v >> (8 * k));
  return p;
}
inline uint8_t *PutOperand(const Fn &f, uint32_t i, uint32_t oi, uint8_t *out, uint64_t key,
                           bool varint, int bytes) {
  const Node &o = f.nodes[oi];
  if (IsConst(o)) {
    if (varint) return PutVar(out, o.val ^ key);
    return PutLE(out, o.val + key, bytes);
  }
  if (o.reg == kSpill) {
    *out++ = 0xFF;
    return PutVar(out, i > oi ? i - oi : oi - i);
  }
  *out++ = (uint8_t)(o.reg | ((i > oi ? i - oi : oi - i) < 16 ? 0x80 : 0));
  return out;
}

template <uint32_t Op> NOINLINE uint8_t *Emit(const Fn &f, uint32_t i, uint8_t *out) {
  constexpr uint32_t ar = Arity(Op);
  constexpr uint64_t K = OpConst(Op, 4);
  constexpr uint32_t layout = (Op >> 4) & 3;
  const Node &n = f.nodes[i];
  if constexpr (Op < 0x80) {
    *out++ = (uint8_t)Op;
  } else {
    *out++ = (uint8_t)(0xC0 | (K & 0x3F));
    *out++ = (uint8_t)Op;
  }
  *out++ = (uint8_t)(((n.reg & 0x3F) << 2) | layout);
  // Scalar (uniform) or vector encoding, operand size.
  *out++ = (uint8_t)((n.type & 0x7F) | (n.op & kDivergentFlag ? 0 : 0x80));
  const uint32_t ops[3] = {n.a, n.b, n.c};
  for (uint32_t k = 0; k < ar; ++k)
    out = PutOperand(f, i, ops[(k + layout) % ar], out, K, (layout & 1) != 0, (Op & 1) ? 4 : 8);
  if constexpr (IsStoreOp(Op)) out = PutVar(out, n.val & 0xFFFF);
  return out;
}

using EmitFn = uint8_t *(*)(const Fn &, uint32_t, uint8_t *);
template <uint32_t... I>
constexpr std::array<EmitFn, sizeof...(I)> EmitTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Emit<I>...}};
}
constexpr auto kEmit = EmitTable(std::make_integer_sequence<uint32_t, kOps>{});
} // namespace

// Backward dataflow over per-block dense bitsets of all SSA values (constants
// and stores excluded), iterated to a fixed point from a post-order worklist.
// Phi sources are live out of their predecessor, not live into the phi block.
void RunLiveness(Fn &f, Arena &ar) {
  uint32_t count = 0;
  for (uint32_t i = 0; i < f.n; ++i) f.nodes[i].liveIdx = NeedsLive(f.nodes[i]) ? count++ : kNone;
  const uint32_t words = std::max(1u, (count + 63) / 64), nb = f.nblocks;
  f.liveCount = count;
  f.liveWords = words;
  f.liveIn = ar.Take<uint64_t>((size_t)nb * words);
  f.liveOut = ar.Take<uint64_t>((size_t)nb * words);
  uint64_t *live = ar.Take<uint64_t>(words);
  uint32_t *work = ar.Take<uint32_t>(nb);
  uint8_t *queued = ar.Take<uint8_t>(nb);
  // Unvisited (deleted) blocks keep empty sets: arena memory holds data of
  // earlier functions, and results must not depend on it.
  std::memset(f.liveIn, 0, (size_t)nb * words * sizeof(uint64_t));
  std::memset(f.liveOut, 0, (size_t)nb * words * sizeof(uint64_t));
  std::memset(queued, 0, nb);
  uint32_t sp = 0;
  for (uint32_t k = 0; k < f.nrpo; ++k) { // pops in post order
    work[sp++] = f.rpoOrder[k];
    queued[f.rpoOrder[k]] = 1;
  }
  auto use = [&](uint32_t v) {
    if (v != kNone && f.nodes[v].liveIdx != kNone) SetBit(live, f.nodes[v].liveIdx);
  };
  while (sp) {
    const uint32_t b = work[--sp];
    queued[b] = 0;
    f.st.liveVisits++;
    const Block &blk = f.blocks[b];
    std::memset(live, 0, words * sizeof(uint64_t));
    for (uint32_t s : blk.succ) {
      if (s == kNone) continue;
      const uint64_t *in = f.liveIn + (size_t)s * words;
      for (uint32_t w = 0; w < words; ++w) live[w] |= in[w];
      for (uint32_t i = f.blocks[s].first; i < f.blocks[s].last && IsPhi(f.nodes[i]); ++i) {
        const Node &p = f.nodes[i];
        if (!IsDead(p)) use(f.phiPred[i] == b ? p.a : p.b);
      }
    }
    std::memcpy(f.liveOut + (size_t)b * words, live, words * sizeof(uint64_t));
    use(blk.cond);
    if (blk.succ[0] == kNone) use(f.ret);
    for (uint32_t i = blk.last; i-- > blk.first;) {
      const Node &n = f.nodes[i];
      if (n.op & (kConstFlag | kDeadFlag)) continue;
      if (n.liveIdx != kNone) ClearBit(live, n.liveIdx);
      if (IsPhi(n)) continue;
      use(n.a);
      use(n.b);
      use(n.c);
    }
    uint64_t *in = f.liveIn + (size_t)b * words;
    if (std::memcmp(in, live, words * sizeof(uint64_t)) != 0) {
      std::memcpy(in, live, words * sizeof(uint64_t));
      for (uint32_t p = 0; p < blk.npred; ++p) {
        const uint32_t pb = f.preds[blk.predFirst + p];
        if (!queued[pb]) {
          queued[pb] = 1;
          work[sp++] = pb;
        }
      }
    }
  }
  f.st.liveBits += (uint64_t)nb * words * 64;
  if (f.diag) {
    for (uint32_t k = 0; k < f.nrpo; ++k) {
      const uint64_t *in = f.liveIn + (size_t)f.rpoOrder[k] * words;
      uint64_t c = 0;
      for (uint32_t w = 0; w < words; ++w) c += (uint64_t)std::popcount(in[w]);
      f.st.liveInSum += c;
      f.st.livePeak = std::max(f.st.livePeak, c);
    }
  }
}

// Per-block list scheduling: phis stay first; other values follow a ready
// list ordered by critical-path height (then program order); stores keep
// their relative order.
void Schedule(Fn &f, Arena &ar) {
  f.order = ar.Take<uint32_t>(f.n);
  f.blockStart = ar.Take<uint32_t>((size_t)f.nblocks + 1);
  uint32_t *npred = ar.Take<uint32_t>(f.n);
  uint32_t *height = ar.Take<uint32_t>(f.n);
  uint32_t *chain = ar.Take<uint32_t>(f.n);
  Heap ready{ar.Take<uint64_t>(f.n)};
  Heap deferred{ar.Take<uint64_t>(f.n)}; // ready but outside the window: min index on top
  uint32_t out = 0;
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    const Block &blk = f.blocks[b];
    f.blockStart[b] = out;
    uint32_t first = blk.first;
    for (; first < blk.last && IsPhi(f.nodes[first]); ++first)
      if (!IsDead(f.nodes[first])) f.order[out++] = first;
    auto inBlock = [&](uint32_t v) {
      return v != kNone && v >= first && v < blk.last && Scheduled(f.nodes[v]);
    };
    uint32_t lastStore = kNone;
    for (uint32_t i = first; i < blk.last; ++i) {
      const Node &n = f.nodes[i];
      chain[i] = kNone;
      if (!Scheduled(n)) continue;
      npred[i] = (uint32_t)inBlock(n.a) + (uint32_t)inBlock(n.b) + (uint32_t)inBlock(n.c);
      if (!IsInput(n) && IsStoreOp(n.op & kOpMask)) {
        if (lastStore != kNone) {
          chain[lastStore] = i;
          npred[i]++;
        }
        lastStore = i;
      }
    }
    // ACO-style bounded motion: a ready instruction is eligible only within
    // kSchedWindow of the oldest unscheduled one (limits register pressure).
    uint32_t low = first;
    auto key = [&](uint32_t i) { return ((uint64_t)height[i] << 32) | (0xFFFFFFFFu - i); };
    auto release = [&](uint32_t i) {
      if (i <= low + kSchedWindow) ready.Push(key(i));
      else deferred.Push(0xFFFFFFFFu - i);
    };
    for (uint32_t i = blk.last; i-- > first;) {
      const Node &n = f.nodes[i];
      if (!Scheduled(n)) continue;
      const uint32_t lat = Latency(n);
      uint32_t h = lat;
      for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
        const uint32_t ui = UseUser(u);
        if (ui > i && ui < blk.last && Scheduled(f.nodes[ui]) && !IsPhi(f.nodes[ui]))
          h = std::max(h, lat + height[ui]);
      }
      if (chain[i] != kNone) h = std::max(h, 1 + height[chain[i]]);
      height[i] = h;
      if (npred[i] == 0) release(i);
    }
    uint32_t expect = first;
    while (ready.n || deferred.n) {
      if (!ready.n) ready.Push(key(0xFFFFFFFFu - (uint32_t)deferred.Pop()));
      const uint32_t i = 0xFFFFFFFFu - (uint32_t)ready.Pop();
      while (expect < blk.last && !Scheduled(f.nodes[expect])) ++expect;
      if (i != expect) f.st.schedMoved++;
      ++expect;
      f.order[out++] = i;
      npred[i] = kNone; // scheduled
      while (low < blk.last && (!Scheduled(f.nodes[low]) || npred[low] == kNone)) ++low;
      while (deferred.n && 0xFFFFFFFFu - (uint32_t)deferred.v[0] <= low + kSchedWindow)
        ready.Push(key(0xFFFFFFFFu - (uint32_t)deferred.Pop()));
      const Node &n = f.nodes[i];
      for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
        const uint32_t ui = UseUser(u);
        if (ui > i && ui < blk.last && Scheduled(f.nodes[ui]) && !IsPhi(f.nodes[ui]) &&
            --npred[ui] == 0)
          release(ui);
      }
      if (chain[i] != kNone && --npred[chain[i]] == 0) release(chain[i]);
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

// Live ranges in schedule positions, one interval per value (holes ignored):
// from the definition (or a live-in block start) to the last use or the end
// of the last block the value is live out of.
void BuildRanges(Fn &f, Arena &ar) {
  f.rangeEnd = ar.Take<uint32_t>(f.liveCount ? f.liveCount : 1);
  const uint32_t words = f.liveWords;
  for (uint32_t i = 0; i < f.n; ++i)
    if (f.nodes[i].liveIdx != kNone) f.rangeEnd[f.nodes[i].liveIdx] = f.nodes[i].pos;
  auto extend = [&](uint32_t v, uint32_t p) {
    if (v == kNone) return;
    const uint32_t l = f.nodes[v].liveIdx;
    if (l != kNone && f.rangeEnd[l] < p) f.rangeEnd[l] = p;
  };
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    if (f.blocks[b].rpo == kNone) continue; // deleted (unreachable)
    const uint32_t end = f.blockStart[b + 1];
    const uint64_t *out = f.liveOut + (size_t)b * words;
    for (uint32_t w = 0; w < words; ++w) {
      for (uint64_t m = out[w]; m; m &= m - 1) {
        const uint32_t v = w * 64 + (uint32_t)std::countr_zero(m);
        if (f.rangeEnd[v] < end) f.rangeEnd[v] = end;
      }
    }
    for (uint32_t k = f.blockStart[b]; k < end; ++k) {
      const Node &n = f.nodes[f.order[k]];
      if (IsPhi(n)) continue;
      extend(n.a, k);
      extend(n.b, k);
      extend(n.c, k);
    }
    extend(f.blocks[b].cond, end);
    if (f.blocks[b].succ[0] == kNone) extend(f.ret, end);
  }
}

// Linear scan over the schedule; when the file is full, spill whichever
// interval ends last.
void RunRegAlloc(Fn &f, Arena &ar) {
  Heap active{ar.Take<uint64_t>(f.n)}; // max-heap of ~(end << 32 | node): min end on top
  uint64_t freeMask = (1ull << kRegs) - 1;
  for (uint32_t k = 0; k < f.norder; ++k) {
    const uint32_t i = f.order[k];
    Node &n = f.nodes[i];
    while (active.n && (uint32_t)(~active.v[0] >> 32) < k) {
      const uint32_t r = f.nodes[(uint32_t)~active.Pop()].reg;
      if (r < kRegs) freeMask |= 1ull << r;
    }
    if (n.liveIdx == kNone) continue; // stores
    const uint32_t end = f.rangeEnd[n.liveIdx];
    if (!freeMask) {
      uint32_t m = 0; // active entry with the furthest end
      for (uint32_t j = 1; j < active.n; ++j)
        if (~active.v[j] > ~active.v[m]) m = j;
      f.st.spills++;
      if (active.n == 0 || (uint32_t)(~active.v[m] >> 32) <= end) {
        n.reg = kSpill;
        continue;
      }
      Node &victim = f.nodes[(uint32_t)~active.v[m]];
      freeMask |= 1ull << victim.reg;
      victim.reg = kSpill;
      // Remove entry m: rebuild the heap property by re-pushing the tail.
      const uint32_t count = active.n;
      uint64_t *tmp = active.v;
      tmp[m] = tmp[count - 1];
      active.n = 0;
      for (uint32_t j = 0; j < count - 1; ++j) active.Push(tmp[j]);
    }
    n.reg = (uint32_t)std::countr_zero(freeMask);
    freeMask &= freeMask - 1;
    active.Push(~(((uint64_t)end << 32) | i));
  }
}

uint64_t EmitAndHash(Fn &f, Arena &ar) {
  uint8_t *buf = ar.Take<uint8_t>((size_t)f.n * 40 + (size_t)f.nblocks * 16 + 128);
  uint8_t *out = buf;
  // Header from gather_info (driver metadata: resource usage, input mask).
  for (uint32_t c : f.info.famCount) out = PutVar(out, c);
  out = PutLE(out, f.info.inputsRead, 8);
  for (uint32_t c : {f.info.stores, f.info.phis, f.info.uniform, f.info.divergent}) out = PutVar(out, c);
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    if (f.blocks[b].rpo == kNone) continue; // deleted (unreachable)
    for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) {
      const Node &n = f.nodes[i];
      if (IsInput(n)) { // input load plus its reflection name
        *out++ = 0xF4;
        *out++ = (uint8_t)n.reg;
        *out++ = (uint8_t)n.op;
        out = PutVar(out, n.name + 1);
        continue;
      }
      if (IsPhi(n)) { // resolved to moves on the incoming edges
        *out++ = 0xF0;
        *out++ = (uint8_t)n.reg;
        *out++ = (uint8_t)f.nodes[n.a].reg;
        *out++ = (uint8_t)f.nodes[n.b].reg;
        continue;
      }
      out = kEmit[n.op & kOpMask](f, i, out);
    }
    const Block &blk = f.blocks[b];
    *out++ = (uint8_t)(0xE0 | (blk.cond != kNone ? 1 : 0) | (blk.succ[0] == kNone ? 2 : 0));
    if (blk.succ[0] != kNone) out = PutVar(out, blk.succ[0]);
    if (blk.cond != kNone) {
      const Node &c = f.nodes[blk.cond];
      out = PutVar(out, blk.succ[1]);
      *out++ = IsConst(c) ? (uint8_t)(0x40 | (c.val & 1)) : (uint8_t)c.reg;
    }
  }
  const size_t len = (size_t)(out - buf);
  f.st.emittedBytes += len;
  uint64_t h = 0x243F6A8885A308D3ull ^ len;
  size_t p = 0;
  for (; p + 8 <= len; p += 8) {
    uint64_t w;
    std::memcpy(&w, buf + p, 8);
    h = Rotl64(h ^ w, 29) * 0x9E3779B97F4A7C15ull;
  }
  for (; p < len; ++p) h = (h ^ buf[p]) * 0x100000001b3ull;
  return h;
}
} // namespace simv5
