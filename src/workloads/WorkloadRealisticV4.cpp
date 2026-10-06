// WorkloadRealisticV4.cpp - Experimental realistic shader-compiler workload (V4).
//
// Opt-in test workload: the `*-simv4` build variant (-DSHADERSTRESS_REALISTIC_V4)
// runs it for `scalar-sim`; every other build keeps the pinned V3
// (WorkloadRealistic.cpp) and only compiles V4 for --self-test / --perf-stats.
//
// V3 matches the package power of real driver shader compiles but not their
// shape (one ~1 KB hot loop, a dense L1 bitvector loop, uniformly random
// opcodes). V4 models an optimizing compiler instead:
//  - large code footprint: 2 x 256 distinct opcode handlers (instruction
//    combining and emission) reached through indirect calls, like pass and
//    visitor code, so the front end (L1i, op cache, BTB) is exercised;
//  - skewed opcode frequencies (geometric over groups of 16, rotated per
//    function like per-shader feature mixes): partly predictable dispatch;
//  - per-function SSA graph with use lists in a bump arena, 1024-16384 nodes
//    (~0.1-2 MiB), mostly local operands with occasional far references;
//  - passes: name interning, IR build, worklist instcombine, hash-based CSE
//    plus a second combine, DCE, linear-scan register allocation, and
//    variable-length emission with a hash of the output.
// Integer only, no unordered containers or unstable sorts: results are
// bit-identical across compilers (required by paired cross-core verification).
#include "core/Common.h"
#include "workloads/Workloads.h"
#include <array>
#include <bit>
#include <cstring>
#include <utility>

namespace {
constexpr uint32_t kOps = 256;           // opcodes = distinct handlers per table
constexpr uint32_t kMinNodes = 64;
constexpr uint32_t kNone = 0xFFFFFFFFu;
constexpr uint32_t kConstFlag = 0x80000000u;
constexpr uint32_t kDeadFlag = 0x40000000u;
constexpr uint32_t kOpMask = 0xFFFFu;
constexpr uint32_t kRegs = 31;           // allocatable registers (GPU-like file)
constexpr uint32_t kNoReg = 0xFD;        // stores and constants
constexpr uint32_t kSpill = 0xFE;
constexpr size_t kPoolBytes = 512 * 1024;            // identifier text pool
constexpr size_t kArenaBytes = 5u * 1024 * 1024;     // per-thread bump arena
constexpr size_t kArenaSlide = 1024 * 1024;          // per-function base slide
// Work per complexity unit: 7/4 IR nodes. Calibrated 2026-10-06 (5700X,
// single-thread --repro 7 4000000) so a job takes about as long as a V3 job;
// benchmark scores are still not comparable with V3.
constexpr uint64_t kNodesPerUnitNum = 7, kNodesPerUnitDen = 4;

constexpr uint64_t OpConst(uint32_t op, uint32_t k) {
  uint64_t z = (uint64_t)op * 0x9E3779B97F4A7C15ull + (uint64_t)k * 0xD1B54A32D192ED03ull;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
constexpr uint32_t Family(uint32_t op) { return op & 7; }
constexpr bool IsStoreOp(uint32_t op) { return (op & 15) == 15; }
constexpr uint32_t Arity(uint32_t op) {
  return IsStoreOp(op) ? 2 : Family(op) == 3 ? 3 : 1 + ((op >> 3) & 1);
}
constexpr bool IsCommutative(uint32_t op) {
  return Arity(op) == 2 && !IsStoreOp(op) && (Family(op) == 0 || Family(op) == 1 || Family(op) == 6);
}

struct Node {
  uint32_t op;        // opcode | kConstFlag | kDeadFlag
  uint32_t a, b, c;   // operand node indices (kNone when unused)
  uint32_t firstUse;  // head of the use list
  uint32_t reg;       // register, kSpill or kNoReg
  uint64_t val;       // constant value or analysis summary
};
struct Use {
  uint32_t user, next;
};
struct InternEntry {
  uint64_t hash;      // 0 = empty
  uint32_t pos, len;
};

struct Ctx {
  Node *nodes = nullptr;
  Use *uses = nullptr;
  uint32_t n = 0, nuses = 0;
  uint32_t *stack = nullptr;   // worklist (deduplicated by inList)
  uint32_t sp = 0;
  uint64_t *inList = nullptr;
  SimV4Diag st;
};

inline uint64_t Next(uint64_t &s) {
  uint64_t z = (s += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
inline bool IsConst(const Node &n) { return (n.op & kConstFlag) != 0; }
inline bool IsDead(const Node &n) { return (n.op & kDeadFlag) != 0; }

inline void Push(Ctx &x, uint32_t i) {
  uint64_t &w = x.inList[i >> 6];
  const uint64_t m = 1ull << (i & 63);
  if (!(w & m)) {
    w |= m;
    x.stack[x.sp++] = i;
  }
}
inline void PushUsers(Ctx &x, uint32_t i) {
  for (uint32_t u = x.nodes[i].firstUse; u != kNone; u = x.uses[u].next)
    if (!IsDead(x.nodes[x.uses[u].user])) Push(x, x.uses[u].user);
}
inline void MakeConst(Ctx &x, uint32_t i, uint64_t v) {
  x.nodes[i].op |= kConstFlag;
  x.nodes[i].val = v;
  x.st.folded++;
  PushUsers(x, i);
}
// Replace all uses of `from` with `to` (to < from, so the graph stays
// topologically ordered), splice the use list over and kill `from`.
void Replace(Ctx &x, uint32_t from, uint32_t to) {
  Node &f = x.nodes[from];
  uint32_t last = kNone;
  for (uint32_t u = f.firstUse; u != kNone; u = x.uses[u].next) {
    const uint32_t ui = x.uses[u].user;
    Node &user = x.nodes[ui];
    if (user.a == from) user.a = to;
    if (user.b == from) user.b = to;
    if (user.c == from) user.c = to;
    if (!IsDead(user)) Push(x, ui);
    last = u;
  }
  if (last != kNone) {
    x.uses[last].next = x.nodes[to].firstUse;
    x.nodes[to].firstUse = f.firstUse;
  }
  f.firstUse = kNone;
  f.op |= kDeadFlag;
}

// --- Instruction combining: one distinct handler per opcode ----------------
template <uint32_t Op> NOINLINE void Fold(Ctx &x, uint32_t i) {
  constexpr uint32_t fam = Family(Op), ar = Arity(Op);
  constexpr uint64_t K1 = OpConst(Op, 1), K2 = OpConst(Op, 2);
  constexpr unsigned R = 1 + (unsigned)(OpConst(Op, 3) % 63);
  Node &n = x.nodes[i];
  x.st.combined++;
  const Node &a = x.nodes[n.a];
  if constexpr (IsStoreOp(Op)) {
    // Side effect: fold the stored value into a memory-state summary.
    const Node &b = x.nodes[n.b];
    n.val = Rotl64(n.val ^ (IsConst(a) ? a.val : (uint64_t)n.a * K1), R) +
            (IsConst(b) ? b.val : K2);
    return;
  } else {
    const Node *b = ar >= 2 ? &x.nodes[n.b] : nullptr;
    const Node *c = ar >= 3 ? &x.nodes[n.c] : nullptr;
    const bool ca = IsConst(a);
    const bool cb = ar < 2 || IsConst(*b);
    const bool cc = ar < 3 || IsConst(*c);
    if (ca && cb && cc) {
      const uint64_t va = a.val, vb = ar >= 2 ? b->val : K2, vc = ar >= 3 ? c->val : K1;
      uint64_t v;
      if constexpr (fam == 0) v = (va + K1) ^ Rotl64(vb, R);
      else if constexpr (fam == 1) v = va * (K1 | 1) - vb;
      else if constexpr (fam == 2) v = (va >> (R & 31)) ^ (vb << (K2 & 31)) ^ K1;
      else if constexpr (fam == 3) v = (vc & 1) ? va : vb;
      else if constexpr (fam == 4) v = (uint64_t)std::popcount(va ^ K1) * (K2 | 1) + vb;
      else if constexpr (fam == 5) v = va / ((vb & 0xFFFFFFFFull) | 1) + K1;
      else if constexpr (fam == 6) v = (va < vb ? va : vb) ^ K2;
      else v = Rotl64(va * 0x9E3779B97F4A7C15ull, R) ^ vb ^ K1;
      MakeConst(x, i, v);
      return;
    }
    if constexpr (fam == 3) {
      if (IsConst(*c)) { // select with known condition
        x.st.peepholes++;
        Replace(x, i, (c->val & 1) ? n.a : n.b);
        return;
      }
    }
    if constexpr (ar >= 2) {
      if constexpr (fam == 0 || fam == 6) {
        if (n.a == n.b) { // x op x
          x.st.peepholes++;
          MakeConst(x, i, K2);
          return;
        }
      }
      if (IsConst(*b) && (b->val & 0xFF) == (Op & 0xFF)) { // x op identity
        x.st.peepholes++;
        Replace(x, i, n.a);
        return;
      }
      if constexpr (IsCommutative(Op)) {
        if (ca && !IsConst(*b)) std::swap(n.a, n.b); // canonical: constant right
      }
    }
    if constexpr (ar == 1 && (Op & 0x30) == 0x10) {
      if (a.op == n.op) { // involution: op(op(x)) -> x
        x.st.peepholes++;
        Replace(x, i, a.a);
        return;
      }
    }
    // Known-bits style summary used by later passes and the checksum.
    n.val = Rotl64((ca ? a.val : K1) ^ ((uint64_t)(a.op & kOpMask) << 32), R) ^ (n.val * (K2 | 1));
  }
}

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

template <uint32_t Op> NOINLINE uint8_t *Emit(const Ctx &x, uint32_t i, uint8_t *out) {
  constexpr uint32_t ar = Arity(Op);
  constexpr uint64_t K = OpConst(Op, 4);
  constexpr uint32_t layout = (Op >> 4) & 3;
  const Node &n = x.nodes[i];
  if constexpr (Op < 0x80) {
    *out++ = (uint8_t)Op;
  } else {
    *out++ = (uint8_t)(0xC0 | (K & 0x3F));
    *out++ = (uint8_t)Op;
  }
  *out++ = (uint8_t)(((n.reg & 0x1F) << 3) | layout);
  const uint32_t ops[3] = {n.a, n.b, n.c};
  for (uint32_t k = 0; k < ar; ++k) {
    const uint32_t oi = ops[(k + layout) % ar];
    const Node &o = x.nodes[oi];
    if (IsConst(o)) {
      if constexpr (layout & 1) out = PutVar(out, o.val ^ K);
      else out = PutLE(out, o.val + K, (Op & 1) ? 4 : 8);
    } else if (o.reg == kSpill) {
      *out++ = 0xFF;
      out = PutVar(out, i - oi);
    } else {
      *out++ = (uint8_t)(o.reg | (i - oi < 16 ? 0x80 : 0));
    }
  }
  if constexpr (IsStoreOp(Op)) out = PutVar(out, n.val & 0xFFFF);
  return out;
}

using FoldFn = void (*)(Ctx &, uint32_t);
using EmitFn = uint8_t *(*)(const Ctx &, uint32_t, uint8_t *);
template <uint32_t... I>
constexpr std::array<FoldFn, sizeof...(I)> FoldTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Fold<I>...}};
}
template <uint32_t... I>
constexpr std::array<EmitFn, sizeof...(I)> EmitTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Emit<I>...}};
}
constexpr auto kFold = FoldTable(std::make_integer_sequence<uint32_t, kOps>{});
constexpr auto kEmit = EmitTable(std::make_integer_sequence<uint32_t, kOps>{});

// Skewed opcode: geometric choice of a group of 16, uniform inside the group,
// rotated by the function's feature mix.
inline uint32_t SkewOp(uint64_t r, uint32_t rot) {
  const uint32_t group = (uint32_t)std::countr_zero(r | (1ull << 40));
  return ((group * 16 + (uint32_t)((r >> 48) & 15)) + rot) & (kOps - 1);
}
inline uint32_t PickOperand(uint32_t i, uint64_t r) {
  if (r & 7) { // mostly local (expression trees)
    const uint32_t d = 1 + (uint32_t)((r >> 3) & 15);
    return d > i ? 0 : i - d;
  }
  return (uint32_t)((r >> 8) % i); // occasional far reference
}

struct Arena {
  uint8_t *base;
  size_t used;
  template <class T> T *Take(size_t count) {
    used = (used + 63) & ~size_t(63);
    T *p = reinterpret_cast<T *>(base + used);
    used += count * sizeof(T);
    return p;
  }
};

struct SimV4Thread {
  std::unique_ptr<uint8_t[]> raw;
  uint8_t *arena = nullptr;
  std::unique_ptr<char[]> pool;
};

SimV4Thread &ThreadState() {
  static thread_local SimV4Thread t;
  if (!t.arena) {
    // Heap with manual 64-byte alignment (PE TLS ignores large alignas).
    t.raw = std::make_unique<uint8_t[]>(kArenaBytes + kArenaSlide + 64);
    t.arena = reinterpret_cast<uint8_t *>((reinterpret_cast<uintptr_t>(t.raw.get()) + 63u) &
                                          ~uintptr_t(63u));
    // Identifier text, identical in every thread and process.
    static constexpr char kChars[] =
        "abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    t.pool = std::make_unique<char[]>(kPoolBytes);
    uint64_t s = 0x5348414445525334ull;
    for (size_t k = 0; k < kPoolBytes; k += 8) {
      const uint64_t r = Next(s);
      for (size_t b = 0; b < 8; ++b) t.pool[k + b] = kChars[(r >> (8 * b)) & 63];
    }
  }
  return t;
}

inline uint64_t Fnv1a(const char *p, uint32_t len) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (uint32_t k = 0; k < len; ++k) {
    h ^= (unsigned char)p[k];
    h *= 0x100000001b3ull;
  }
  return h | 1;
}

uint64_t InternNames(Arena &ar, const char *pool, uint32_t names, uint64_t &rng, SimV4Diag &st) {
  const uint32_t size = std::bit_ceil(names * 2);
  InternEntry *table = ar.Take<InternEntry>(size);
  std::memset(table, 0, size * sizeof(InternEntry));
  uint64_t acc = 0;
  for (uint32_t k = 0; k < names; ++k) {
    const uint64_t r = Next(rng);
    const uint64_t id = (uint64_t)std::countr_zero(r | (1ull << 20)) * 64 + ((r >> 40) & 63);
    const uint64_t m = OpConst((uint32_t)id, 9);
    const uint32_t pos = (uint32_t)(m % (kPoolBytes - 64)), len = 4 + (uint32_t)((m >> 40) % 28);
    const uint64_t h = Fnv1a(pool + pos, len);
    for (uint32_t s = (uint32_t)h & (size - 1);; s = (s + 1) & (size - 1)) {
      InternEntry &e = table[s];
      if (e.hash == 0) {
        e = {h, pos, len};
        break;
      }
      if (e.hash == h && e.len == len && std::memcmp(pool + e.pos, pool + pos, len) == 0) {
        st.internHits++;
        break;
      }
    }
    acc = Rotl64(acc ^ h, 13) + k;
  }
  return acc;
}

void BuildIr(Ctx &x, uint64_t &rng, uint32_t rot) {
  // Expression-tree shape: most values feed one of the next instructions
  // (pending stack of unused values); ~1/16 of instructions repeat a recent
  // expression (common subexpressions such as address arithmetic).
  uint32_t pending[32];
  uint32_t np = 0;
  for (uint32_t i = 0; i < x.n; ++i) {
    const uint64_t r = Next(rng);
    Node &nd = x.nodes[i];
    nd.firstUse = kNone;
    nd.reg = kNoReg;
    nd.a = nd.b = nd.c = kNone;
    if (i < 4 || (r & 7) == 0) {
      nd.op = SkewOp(r >> 3, rot) | kConstFlag;
      nd.val = ((r >> 40) & 1) ? ((r >> 12) & 0xFF) : Next(rng); // small constants are common
      continue;
    }
    nd.val = 0;
    uint32_t *slots[3] = {&nd.a, &nd.b, &nd.c};
    const uint32_t src = i - 1 - (uint32_t)((r >> 52) % std::min<uint32_t>(i, 64));
    if (((r >> 3) & 15) == 0 && !IsConst(x.nodes[src]) && !IsStoreOp(x.nodes[src].op & kOpMask)) {
      nd.op = x.nodes[src].op; // duplicate of a recent expression
      const uint32_t ops[3] = {x.nodes[src].a, x.nodes[src].b, x.nodes[src].c};
      for (uint32_t k = 0; k < Arity(nd.op); ++k) *slots[k] = ops[k];
    } else {
      nd.op = SkewOp(r, rot);
      for (uint32_t k = 0; k < Arity(nd.op); ++k) {
        const uint64_t q = Next(rng);
        *slots[k] = (np && (q & 3) != 0) ? pending[--np] : PickOperand(i, q);
      }
    }
    for (uint32_t k = 0; k < Arity(nd.op); ++k) {
      const uint32_t o = *slots[k];
      x.uses[x.nuses] = {i, x.nodes[o].firstUse};
      x.nodes[o].firstUse = x.nuses++;
    }
    if (!IsStoreOp(nd.op)) {
      if (np == 32) { // oldest pending value becomes a far reference later
        for (uint32_t k = 1; k < 32; ++k) pending[k - 1] = pending[k];
        --np;
      }
      pending[np++] = i;
    }
  }
}

void RunCombine(Ctx &x) {
  while (x.sp) {
    const uint32_t i = x.stack[--x.sp];
    x.inList[i >> 6] &= ~(1ull << (i & 63));
    const Node &n = x.nodes[i];
    if (n.op & (kConstFlag | kDeadFlag)) continue;
    kFold[n.op & kOpMask](x, i);
  }
}

void RunCse(Ctx &x, Arena &ar) {
  const uint32_t size = std::bit_ceil(x.n * 2);
  uint32_t *table = ar.Take<uint32_t>(size);
  std::memset(table, 0, size * sizeof(uint32_t));
  for (uint32_t i = 0; i < x.n; ++i) {
    const Node &n = x.nodes[i];
    if ((n.op & (kConstFlag | kDeadFlag)) || IsStoreOp(n.op & kOpMask)) continue;
    uint64_t h = OpConst(n.op, n.a) ^ ((uint64_t)n.b << 21) ^ ((uint64_t)n.c << 42);
    h ^= h >> 29;
    for (uint32_t s = (uint32_t)h & (size - 1);; s = (s + 1) & (size - 1)) {
      if (table[s] == 0) {
        table[s] = i + 1;
        break;
      }
      const uint32_t j = table[s] - 1;
      const Node &m = x.nodes[j];
      if (m.op == n.op && m.a == n.a && m.b == n.b && m.c == n.c) {
        x.st.cseHits++;
        Replace(x, i, j);
        break;
      }
    }
  }
}

// Marks live nodes from the side-effect roots and kills the rest.
void RunDce(Ctx &x, Arena &ar) {
  const uint32_t words = (x.n + 63) / 64;
  uint64_t *live = ar.Take<uint64_t>(words);
  std::memset(live, 0, words * sizeof(uint64_t));
  uint32_t sp = 0;
  auto mark = [&](uint32_t i) {
    if (i == kNone || IsDead(x.nodes[i]) || (live[i >> 6] >> (i & 63)) & 1) return;
    live[i >> 6] |= 1ull << (i & 63);
    x.stack[sp++] = i;
  };
  for (uint32_t i = 0; i < x.n; ++i)
    if (IsStoreOp(x.nodes[i].op & kOpMask) && !IsConst(x.nodes[i])) mark(i);
  mark(x.n - 1);
  while (sp) {
    const Node &n = x.nodes[x.stack[--sp]];
    if (IsConst(n)) continue; // constants have no dependencies
    mark(n.a);
    mark(n.b);
    mark(n.c);
  }
  for (uint32_t i = 0; i < x.n; ++i) {
    if (!((live[i >> 6] >> (i & 63)) & 1) && !IsDead(x.nodes[i])) {
      x.nodes[i].op |= kDeadFlag;
      x.st.dead++;
    }
  }
}

// Linear scan over the topological order; intervals end at the last live use.
void RunRegAlloc(Ctx &x, Arena &ar) {
  uint64_t *heap = ar.Take<uint64_t>(x.n); // (end << 32 | node), min-heap
  uint32_t hs = 0, freeMask = (1u << kRegs) - 1;
  auto siftDown = [&](uint32_t k) {
    for (;;) {
      uint32_t c = 2 * k + 1;
      if (c >= hs) break;
      if (c + 1 < hs && heap[c + 1] < heap[c]) ++c;
      if (heap[k] <= heap[c]) break;
      std::swap(heap[k], heap[c]);
      k = c;
    }
  };
  auto siftUp = [&](uint32_t k) {
    while (k && heap[(k - 1) / 2] > heap[k]) {
      std::swap(heap[(k - 1) / 2], heap[k]);
      k = (k - 1) / 2;
    }
  };
  for (uint32_t i = 0; i < x.n; ++i) {
    Node &n = x.nodes[i];
    if (n.op & (kConstFlag | kDeadFlag)) continue;
    while (hs && (uint32_t)(heap[0] >> 32) < i) {
      const uint32_t r = x.nodes[(uint32_t)heap[0]].reg;
      heap[0] = heap[--hs];
      siftDown(0);
      if (r < kRegs) freeMask |= 1u << r;
    }
    if (IsStoreOp(n.op & kOpMask)) continue;
    uint32_t end = i;
    for (uint32_t u = n.firstUse; u != kNone; u = x.uses[u].next) {
      const uint32_t ui = x.uses[u].user;
      if (!IsDead(x.nodes[ui]) && ui > end) end = ui;
    }
    if (!freeMask) {
      // Linear-scan heuristic: spill whichever interval ends last.
      uint32_t m = 0;
      for (uint32_t k = 1; k < hs; ++k)
        if (heap[k] > heap[m]) m = k;
      x.st.spills++;
      if (hs == 0 || (uint32_t)(heap[m] >> 32) <= end) {
        n.reg = kSpill;
        continue;
      }
      Node &victim = x.nodes[(uint32_t)heap[m]];
      freeMask |= 1u << victim.reg;
      victim.reg = kSpill;
      heap[m] = heap[--hs];
      if (m < hs) {
        siftDown(m);
        siftUp(m);
      }
    }
    n.reg = (uint32_t)std::countr_zero(freeMask);
    freeMask &= freeMask - 1;
    heap[hs] = ((uint64_t)end << 32) | i;
    siftUp(hs++);
  }
}

uint64_t EmitAndHash(Ctx &x, Arena &ar) {
  uint8_t *buf = ar.Take<uint8_t>((size_t)x.n * 40 + 8);
  uint8_t *out = buf;
  for (uint32_t i = 0; i < x.n; ++i) {
    const Node &n = x.nodes[i];
    if (n.op & (kConstFlag | kDeadFlag)) continue;
    out = kEmit[n.op & kOpMask](x, i, out);
  }
  const size_t len = (size_t)(out - buf);
  x.st.emittedBytes += len;
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

uint64_t CompileFunction(SimV4Thread &t, uint32_t nodes, uint64_t &rng, uint64_t funcIndex,
                         SimV4Diag &st) {
  // Bump arena reset per function; the base slides like a real allocator's slabs.
  Arena ar{t.arena + ((funcIndex * 64 * 67) % kArenaSlide), 0};
  Ctx x;
  x.n = nodes;
  x.nodes = ar.Take<Node>(nodes);
  x.uses = ar.Take<Use>((size_t)nodes * 3);
  x.stack = ar.Take<uint32_t>(nodes);
  const uint32_t words = (nodes + 63) / 64;
  x.inList = ar.Take<uint64_t>(words);
  std::memset(x.inList, 0, words * sizeof(uint64_t));
  x.st = st;

  const uint32_t rot = (uint32_t)(Next(rng) & (kOps - 1));
  uint64_t acc = InternNames(ar, t.pool.get(), std::max(8u, nodes / 32), rng, x.st);
  BuildIr(x, rng, rot);
  for (uint32_t i = nodes; i-- > 0;) Push(x, i); // pops in program order
  RunCombine(x);
  RunCse(x, ar);
  RunCombine(x); // users of merged values
  RunDce(x, ar);
  RunRegAlloc(x, ar);
  acc = Rotl64(acc, 7) ^ EmitAndHash(x, ar);
  for (uint32_t i = 0; i < nodes; i += 61) // sample the analysis summaries
    acc = Rotl64(acc ^ x.nodes[i].val ^ x.nodes[i].op, 11) * 0x9E3779B97F4A7C15ull;
  x.st.functions++;
  x.st.nodes += nodes;
  st = x.st;
  return acc;
}
} // namespace

uint64_t RunRealisticCompilerSimV4Diag(uint64_t seed, int complexity, SimV4Diag *diag) {
  SimV4Thread &t = ThreadState();
  SimV4Diag st;
  uint64_t rng = seed ^ 0x52454C3456345349ull;
  uint64_t budget = (uint64_t)std::clamp(complexity, 1, MAX_JOB_COMPLEXITY) * kNodesPerUnitNum /
                    kNodesPerUnitDen;
  if (budget == 0) budget = 1;
  uint64_t acc = seed, funcIndex = 0;
  while (budget) {
    if (StopRequested()) [[unlikely]] {
      st.aborted = true;
      break;
    }
    // Shader sizes: mostly small, occasionally large (1024..16384 nodes).
    const uint32_t g = std::min(4u, (uint32_t)std::countr_zero(Next(rng) | 16u));
    uint32_t nodes = 1024u << g;
    if (nodes > budget) nodes = (uint32_t)std::max<uint64_t>(budget, kMinNodes);
    budget -= std::min<uint64_t>(budget, nodes);
    acc = Rotl64(acc, 23) ^ CompileFunction(t, nodes, rng, funcIndex++, st);
  }
  if (diag) *diag = st;
  volatile uint64_t sink = acc;
  (void)sink;
  return acc;
}

uint64_t RunRealisticCompilerSim_V4(uint64_t seed, int complexity, const StressConfig &config) {
  (void)config;
  return RunRealisticCompilerSimV4Diag(seed, complexity, nullptr);
}
