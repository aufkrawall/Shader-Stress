// WorkloadRealisticV5Back.cpp - Realistic V5 back end: instruction indexing
// (per-block instruction vectors in list order, like nir_index_instrs / ACO's
// blocks), dense-bitset block liveness (NIR-style iterative dataflow),
// per-block list scheduling on a dependence DAG with a critical-path priority
// queue, live ranges, linear-scan register allocation and per-opcode encoders
// with a hash of the binary.
#include "workloads/WorkloadRealisticV5.h"
#include <array>
#include <utility>

namespace simv5 {
namespace {
inline bool NeedsLive(const Node &n) { return !(n.op & (kConstFlag | kDeadFlag)) && n.type != kVoid; }
constexpr uint32_t kSchedWindow = 24;
inline bool Scheduled(const Node &n) { return !(n.op & (kConstFlag | kDeadFlag)); }
inline uint32_t Latency(const Node &n) { return IsPhi(n) ? 0 : 1 + Info(OpOf(n)).latency; }
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
inline uint8_t *PutOperand(const Fn &f, uint32_t pos, uint32_t oi, uint8_t *out, uint64_t key, bool varint) {
  const Node &o = f.nodes[oi];
  if (IsConst(o)) { // literal constant (32-bit inline / literal dword)
    if (varint) return PutVar(out, (o.val ^ key) & 0xFFFFFFFFu);
    return PutLE(out, o.val + key, 4);
  }
  const uint32_t d = pos > o.pos ? pos - o.pos : o.pos - pos;
  if (o.reg == kSpill) {
    *out++ = 0xFF;
    return PutVar(out, d);
  }
  *out++ = (uint8_t)(o.reg | (d < 16 ? 0x80 : 0));
  return out;
}

template <uint32_t Op> NOINLINE uint8_t *Emit(const Fn &f, uint32_t i, uint8_t *out) {
  constexpr uint32_t ar = Arity(Op);
  constexpr uint64_t K = OpConst(Op, 4);
  constexpr uint32_t layout = (Op >> 4) & 3;
  const Node &n = f.nodes[i];
  if constexpr (Op < 0x40) {
    *out++ = (uint8_t)Op;
  } else {
    *out++ = (uint8_t)(0xC0 | (K & 0x3F));
    *out++ = (uint8_t)Op;
  }
  *out++ = (uint8_t)(((n.reg & 0x3F) << 2) | layout);
  // Scalar (uniform) or vector encoding, result type; extract index.
  *out++ = (uint8_t)((n.type & 0x3F) | (n.imm << 6 & 0x40) | (n.op & kDivergentFlag ? 0 : 0x80));
  const uint32_t ops[3] = {n.a, n.b, n.c};
  for (uint32_t k = 0; k < ar; ++k) out = PutOperand(f, n.pos, ops[(k + layout) % ar], out, K, (layout & 1) != 0);
  if constexpr (HasFlag(Op, kMemRead) || IsStoreOp(Op)) out = PutVar(out, n.name + 1); // reflection name
  return out;
}

using EmitFn = uint8_t *(*)(const Fn &, uint32_t, uint8_t *);
template <uint32_t... I>
constexpr std::array<EmitFn, sizeof...(I)> EmitTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Emit<I>...}};
}
constexpr auto kEmit = EmitTable(std::make_integer_sequence<uint32_t, kOpCount>{});
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

// Backward dataflow over per-block dense bitsets of all SSA values (constants
// and void instructions excluded), iterated to a fixed point from a post-order
// worklist. Phi sources are live out of their predecessor, not live into the
// phi block.
void RunLiveness(Fn &f, Arena &ar) {
  uint32_t count = 0;
  for (uint32_t k = 0; k < f.nseq; ++k) {
    Node &n = f.nodes[f.seq[k]];
    n.liveIdx = NeedsLive(n) ? count++ : kNone;
  }
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
    if (v != kNone && f.nodes[v].liveIdx != kNone && !IsDead(f.nodes[v])) SetBit(live, f.nodes[v].liveIdx);
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
      for (uint32_t k = f.seqStart[s]; k < f.seqStart[s + 1] && IsPhi(f.nodes[f.seq[k]]); ++k) {
        const uint32_t i = f.seq[k];
        use(f.phiPred[i] == b ? f.nodes[i].a : f.nodes[i].b);
      }
    }
    std::memcpy(f.liveOut + (size_t)b * words, live, words * sizeof(uint64_t));
    use(blk.cond);
    for (uint32_t k = f.seqStart[b + 1]; k-- > f.seqStart[b];) {
      const Node &n = f.nodes[f.seq[k]];
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

// Live ranges in schedule positions, one interval per value (holes ignored):
// from the definition (or a live-in block start) to the last use or the end
// of the last block the value is live out of.
void BuildRanges(Fn &f, Arena &ar) {
  f.rangeEnd = ar.Take<uint32_t>(f.liveCount ? f.liveCount : 1);
  const uint32_t words = f.liveWords;
  for (uint32_t k = 0; k < f.norder; ++k) {
    const Node &n = f.nodes[f.order[k]];
    if (n.liveIdx != kNone) f.rangeEnd[n.liveIdx] = n.pos;
  }
  auto extend = [&](uint32_t v, uint32_t p) {
    if (v == kNone || IsDead(f.nodes[v])) return;
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
  }
}

// Linear scan over the schedule; when the file is full, spill whichever
// interval ends last.
void RunRegAlloc(Fn &f, Arena &ar) {
  Heap active{ar.Take<uint64_t>(f.norder + 1)}; // max-heap of ~(end << 32 | node): min end on top
  uint64_t freeMask = (1ull << kRegs) - 1;
  for (uint32_t k = 0; k < f.norder; ++k) {
    const uint32_t i = f.order[k];
    Node &n = f.nodes[i];
    while (active.n && (uint32_t)(~active.v[0] >> 32) < k) {
      const uint32_t r = f.nodes[(uint32_t)~active.Pop()].reg;
      if (r < kRegs) freeMask |= 1ull << r;
    }
    if (n.liveIdx == kNone) continue; // void instructions
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
  uint8_t *buf = ar.Take<uint8_t>((size_t)f.norder * 40 + (size_t)f.nblocks * 16 + 128);
  uint8_t *out = buf;
  // Header from gather_info (driver metadata: resource usage, input mask).
  for (uint32_t c : f.info.unitCount) out = PutVar(out, c);
  out = PutLE(out, f.info.inputsRead, 8);
  for (uint32_t c : {f.info.stores, f.info.phis, f.info.uniform, f.info.divergent}) out = PutVar(out, c);
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    if (f.blocks[b].rpo == kNone) continue; // deleted (unreachable)
    for (uint32_t i = f.blocks[b].head; i != kNone; i = f.nodes[i].next) {
      const Node &n = f.nodes[i];
      if (IsPhi(n)) { // resolved to moves on the incoming edges
        *out++ = 0xF0;
        *out++ = (uint8_t)n.reg;
        *out++ = (uint8_t)f.nodes[n.a].reg;
        *out++ = (uint8_t)f.nodes[n.b].reg;
        continue;
      }
      out = kEmit[OpOf(n)](f, i, out);
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
