// WorkloadRealisticV5Opt.cpp - Realistic V5 middle end: generated per-opcode
// combine handlers (instcombine / nir_opt_algebraic style) on a worklist, phi
// simplification, dominator tree, scoped dominator-tree CSE and DCE.
#include "workloads/WorkloadRealisticV5.h"
#include <array>
#include <utility>

namespace simv5 {
namespace {
inline void Push(Fn &f, uint32_t i) {
  uint64_t &w = f.inList[i >> 6];
  const uint64_t m = 1ull << (i & 63);
  if (!(w & m)) {
    w |= m;
    f.stack[f.sp++] = i;
  }
}
inline void PushUsers(Fn &f, uint32_t i) {
  for (uint32_t u = f.nodes[i].firstUse; u != kNone; u = f.UseNext(u))
    if (!IsDead(f.nodes[UseUser(u)])) Push(f, UseUser(u));
}
// Operands that lost a use go back on the worklist (they may be dead now).
inline void ReleaseOperands(Fn &f, uint32_t i, bool erase) {
  const Node &n = f.nodes[i];
  const uint32_t ops[3] = {n.a, n.b, n.c}, count = NumOperands(n);
  if (erase) EraseNode(f, i);
  else DropOperands(f, i);
  for (uint32_t k = 0; k < count; ++k)
    if (!(f.nodes[ops[k]].op & (kConstFlag | kDeadFlag))) Push(f, ops[k]);
}
// The instruction folds to a constant: it leaves the instruction list (its
// users keep referring to the node, now a constant).
inline void MakeConst(Fn &f, uint32_t i, uint64_t v) {
  ReleaseOperands(f, i, false);
  Unlink(f, i);
  f.nodes[i].op |= kConstFlag;
  f.nodes[i].val = v;
  f.st.folded++;
  PushUsers(f, i);
}

// Replace all uses of `from` with `to` (`to` dominates `from`; LLVM
// replaceAllUsesWith), splice the use list over and erase `from`. Terminator
// operands follow the replacement.
void Replace(Fn &f, uint32_t from, uint32_t to) {
  Node &n = f.nodes[from];
  uint32_t last = kNone;
  for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
    const uint32_t ui = UseUser(u);
    OperandRef(f.nodes[ui], u & 3) = to;
    if (!IsDead(f.nodes[ui])) Push(f, ui);
    last = u;
  }
  if (last != kNone) {
    Node &t = f.nodes[to];
    f.UseNext(last) = t.firstUse;
    if (t.firstUse != kNone) f.UsePrev(t.firstUse) = last;
    t.firstUse = n.firstUse;
    t.numUses += n.numUses;
  }
  if (n.op & kCondFlag) {
    for (uint32_t b = 0; b < f.nblocks; ++b)
      if (f.blocks[b].cond == from) f.blocks[b].cond = to;
    if (f.ret == from) f.ret = to;
    f.nodes[to].op |= kCondFlag;
  }
  n.firstUse = kNone;
  n.numUses = 0;
  ReleaseOperands(f, from, true);
}

template <uint32_t Op> NOINLINE void Fold(Fn &f, uint32_t i) {
  constexpr uint32_t fam = Family(Op), ar = Arity(Op);
  constexpr uint64_t K1 = OpConst(Op, 1), K2 = OpConst(Op, 2);
  constexpr unsigned R = 1 + (unsigned)(OpConst(Op, 3) % 63);
  Node &n = f.nodes[i];
  f.st.combined++;
  const Node &a = f.nodes[n.a];
  if constexpr (IsStoreOp(Op)) {
    // Side effect: fold the stored value into a memory-state summary.
    const Node &b = f.nodes[n.b];
    n.val = Rotl64(n.val ^ (IsConst(a) ? a.val : (uint64_t)n.a * K1), R) +
            (IsConst(b) ? b.val : K2);
    return;
  } else {
    const Node *b = ar >= 2 ? &f.nodes[n.b] : nullptr;
    const Node *c = ar >= 3 ? &f.nodes[n.c] : nullptr;
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
      MakeConst(f, i, v);
      return;
    }
    if constexpr (fam == 3) {
      if (IsConst(*c)) { // select with known condition
        f.st.peepholes++;
        Replace(f, i, (c->val & 1) ? n.a : n.b);
        return;
      }
    }
    if constexpr (ar >= 2) {
      if constexpr (fam == 0 || fam == 6) {
        if (n.a == n.b) { // x op x
          f.st.peepholes++;
          MakeConst(f, i, K2);
          return;
        }
      }
      if (IsConst(*b) && (b->val & 0xFF) == (Op & 0xFF)) { // x op identity
        f.st.peepholes++;
        Replace(f, i, n.a);
        return;
      }
      if constexpr (IsCommutative(Op)) {
        if (ca && !IsConst(*b)) SwapOperands(f, i); // canonical: constant right
      }
    }
    if constexpr (ar == 1 && (Op & 0x30) == 0x10) {
      if ((a.op & (kOpMask | kConstFlag | kPhiFlag | kInputFlag)) == Op) { // involution: op(op(x)) -> x
        f.st.peepholes++;
        Replace(f, i, a.a);
        return;
      }
    }
    // Known-bits style summary used by later passes and the checksum.
    n.val = Rotl64((ca ? a.val : K1) ^ ((uint64_t)(a.op & kOpMask) << 32), R) ^ (n.val * (K2 | 1));
  }
}

using FoldFn = void (*)(Fn &, uint32_t);
template <uint32_t... I>
constexpr std::array<FoldFn, sizeof...(I)> FoldTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Fold<I>...}};
}
constexpr auto kFold = FoldTable(std::make_integer_sequence<uint32_t, kOps>{});

// phi(x, x) / phi(x, self) -> x; phi of equal constants -> constant.
void SimplifyPhi(Fn &f, uint32_t i) {
  const Node &n = f.nodes[i];
  const uint32_t other = n.b == i ? n.a : n.a == i ? n.b : n.a == n.b ? n.a : kNone;
  if (other != kNone && other < i) {
    f.st.peepholes++;
    Replace(f, i, other);
    return;
  }
  const Node &a = f.nodes[n.a], &b = f.nodes[n.b];
  if (IsConst(a) && IsConst(b) && a.val == b.val) MakeConst(f, i, a.val);
}
} // namespace

void RebuildPreds(Fn &f) {
  for (uint32_t b = 0; b < f.nblocks; ++b) f.blocks[b].npred = 0;
  for (uint32_t b = 0; b < f.nblocks; ++b)
    for (uint32_t s : f.blocks[b].succ)
      if (s != kNone) f.blocks[s].npred++;
  uint32_t off = 0;
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    f.blocks[b].predFirst = off;
    off += f.blocks[b].npred;
    f.blocks[b].npred = 0;
  }
  for (uint32_t b = 0; b < f.nblocks; ++b)
    for (uint32_t s : f.blocks[b].succ)
      if (s != kNone) f.preds[f.blocks[s].predFirst + f.blocks[s].npred++] = b;
}

namespace {
// Edge pred -> s disappears: each phi of s keeps only its other operand. A
// phi whose remaining value is defined later (loop back edge) stays.
void RemovePhiEdge(Fn &f, uint32_t s, uint32_t pred) {
  for (uint32_t i = f.blocks[s].first; i < f.blocks[s].last && IsPhi(f.nodes[i]); ++i) {
    const Node &p = f.nodes[i];
    if (IsDead(p)) continue;
    const uint32_t other = f.phiPred[i] == pred ? p.b : p.a;
    if (other < i) {
      f.st.peepholes++;
      Replace(f, i, other);
    }
  }
}
} // namespace

// Dead control flow (nir_opt_dead_cf / SimplifyCFG): a forward branch on a
// constant condition (specialization constant, folded compare) loses its
// untaken edge; blocks that become unreachable are deleted, and phis are
// reduced to the value of the remaining predecessor. Loop latches keep their
// exit edge (no infinite loops). Returns whether the CFG changed.
bool RunDeadCf(Fn &f, Arena &ar) {
  bool changed = false;
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    Block &blk = f.blocks[b];
    if (blk.cond == kNone || !IsConst(f.nodes[blk.cond]) || blk.succ[0] <= b || blk.succ[1] <= b)
      continue;
    const bool taken = (f.nodes[blk.cond].val & 1) != 0;
    const uint32_t keep = taken ? blk.succ[0] : blk.succ[1], drop = taken ? blk.succ[1] : blk.succ[0];
    blk.succ[0] = keep;
    blk.succ[1] = kNone;
    blk.cond = kNone;
    f.st.branchesFolded++;
    RemovePhiEdge(f, drop, b);
    changed = true;
  }
  if (!changed) return false;
  uint8_t *reach = ar.Take<uint8_t>(f.nblocks);
  uint32_t *work = ar.Take<uint32_t>(f.nblocks);
  std::memset(reach, 0, f.nblocks);
  uint32_t sp = 0;
  reach[0] = 1;
  work[sp++] = 0;
  while (sp) {
    for (uint32_t s : f.blocks[work[--sp]].succ) {
      if (s != kNone && !reach[s]) {
        reach[s] = 1;
        work[sp++] = s;
      }
    }
  }
  for (uint32_t b = 0; b < f.nblocks; ++b) {
    Block &blk = f.blocks[b];
    if (reach[b] || (blk.succ[0] == kNone && blk.first == blk.last)) continue;
    for (uint32_t s : blk.succ)
      if (s != kNone && reach[s]) RemovePhiEdge(f, s, b);
    for (uint32_t i = blk.first; i < blk.last; ++i) {
      if (IsDead(f.nodes[i])) continue;
      EraseNode(f, i);
      f.st.dead++;
    }
    blk.succ[0] = blk.succ[1] = kNone;
    blk.cond = kNone;
    blk.first = blk.last; // deleted
    f.st.deadBlocks++;
  }
  RebuildPreds(f);
  return true;
}

void PushAll(Fn &f) {
  for (uint32_t i = f.n; i-- > f.nconst;) Push(f, i); // pops in program order
}

void RunCombine(Fn &f) {
  while (f.sp) {
    const uint32_t i = f.stack[--f.sp];
    f.inList[i >> 6] &= ~(1ull << (i & 63));
    const Node &n = f.nodes[i];
    if (n.op & (kConstFlag | kDeadFlag)) continue;
    // Trivially dead (InstCombine erases these first): no uses, no side effect.
    if (n.numUses == 0 && !(n.op & kCondFlag) && !IsStore(n)) {
      ReleaseOperands(f, i, true);
      f.st.dead++;
      continue;
    }
    if (IsInput(n)) continue;
    if (IsPhi(n)) SimplifyPhi(f, i);
    else kFold[n.op & kOpMask](f, i);
  }
}

// Cooper, Harvey, Kennedy: "A Simple, Fast Dominance Algorithm".
void BuildDominators(Fn &f, Arena &ar) {
  const uint32_t nb = f.nblocks;
  f.rpoOrder = ar.Take<uint32_t>(nb);
  uint32_t *dfs = ar.Take<uint32_t>(nb * 2);
  uint32_t sp = 0, post = nb;
  for (uint32_t b = 0; b < nb; ++b) f.blocks[b].rpo = kNone;
  // Iterative DFS: stack of (block, next successor slot); rpo = visited mark.
  f.blocks[0].rpo = 0;
  dfs[sp++] = 0;
  dfs[sp++] = 0;
  while (sp) {
    const uint32_t b = dfs[sp - 2], k = dfs[sp - 1];
    if (k < kMaxSucc) {
      dfs[sp - 1] = k + 1;
      const uint32_t s = f.blocks[b].succ[k];
      if (s != kNone && f.blocks[s].rpo == kNone) {
        f.blocks[s].rpo = 0;
        dfs[sp++] = s;
        dfs[sp++] = 0;
      }
    } else {
      sp -= 2;
      f.rpoOrder[--post] = b;
    }
  }
  // Every generated block is reachable; compact in case one is not.
  const uint32_t first = post;
  for (uint32_t k = first; k < nb; ++k) f.blocks[f.rpoOrder[k]].rpo = k - first;
  f.nrpo = nb - first;
  f.rpoOrder += first;
  for (uint32_t b = 0; b < nb; ++b) f.blocks[b].idom = b == 0 ? 0 : kNone;
  for (bool changed = true; changed;) {
    changed = false;
    f.st.domIters++;
    for (uint32_t k = 1; k < f.nrpo; ++k) {
      const uint32_t b = f.rpoOrder[k];
      const Block &blk = f.blocks[b];
      uint32_t idom = kNone;
      for (uint32_t p = 0; p < blk.npred; ++p) {
        uint32_t x = f.preds[blk.predFirst + p];
        if (f.blocks[x].idom == kNone) continue;
        if (idom == kNone) {
          idom = x;
          continue;
        }
        uint32_t y = idom;
        while (x != y) {
          while (f.blocks[x].rpo > f.blocks[y].rpo) x = f.blocks[x].idom;
          while (f.blocks[y].rpo > f.blocks[x].rpo) y = f.blocks[y].idom;
        }
        idom = x;
      }
      if (idom != blk.idom) {
        f.blocks[b].idom = idom;
        changed = true;
      }
    }
  }
  // Dominator tree as child / sibling lists (children in reverse RPO order).
  for (uint32_t b = 0; b < nb; ++b) f.blocks[b].domChild = f.blocks[b].domSibling = kNone;
  for (uint32_t k = f.nrpo; k-- > 1;) {
    const uint32_t b = f.rpoOrder[k];
    Block &parent = f.blocks[f.blocks[b].idom];
    f.blocks[b].domSibling = parent.domChild;
    parent.domChild = b;
  }
}

// EarlyCSE: preorder walk of the dominator tree with a scoped hash table, so
// an expression is replaced only by an equal one that dominates it. Scopes
// are popped in LIFO order, which restores the linear-probing table exactly.
void RunCse(Fn &f, Arena &ar) {
  const uint32_t size = std::bit_ceil(f.n * 2);
  uint32_t *table = ar.Take<uint32_t>(size);
  uint32_t *undo = ar.Take<uint32_t>(f.n);
  uint32_t *walk = ar.Take<uint32_t>((size_t)f.nblocks * 2);
  std::memset(table, 0, size * sizeof(uint32_t));
  uint32_t nundo = 0, sp = 0;
  walk[sp++] = 0;
  walk[sp++] = kNone; // enter marker
  while (sp) {
    const uint32_t b = walk[sp - 2], mark = walk[sp - 1];
    if (mark != kNone) { // leave: drop this block's scope
      while (nundo > mark) table[undo[--nundo]] = 0;
      sp -= 2;
      continue;
    }
    walk[sp - 1] = nundo;
    for (uint32_t i = f.blocks[b].first; i < f.blocks[b].last; ++i) {
      const Node &n = f.nodes[i];
      if ((n.op & (kConstFlag | kDeadFlag | kPhiFlag | kInputFlag)) || IsStoreOp(n.op & kOpMask))
        continue;
      const uint32_t op = n.op & kOpMask;
      uint64_t h = OpConst(op, n.a) ^ ((uint64_t)n.b << 21) ^ ((uint64_t)n.c << 42);
      h ^= h >> 29;
      for (uint32_t s = (uint32_t)h & (size - 1);; s = (s + 1) & (size - 1)) {
        if (table[s] == 0) {
          table[s] = i + 1;
          undo[nundo++] = s;
          break;
        }
        const Node &m = f.nodes[table[s] - 1];
        if ((m.op & kOpMask) == op && m.type == n.type && m.a == n.a && m.b == n.b && m.c == n.c) {
          f.st.cseHits++;
          Replace(f, i, table[s] - 1);
          break;
        }
      }
    }
    for (uint32_t c = f.blocks[b].domChild; c != kNone; c = f.blocks[c].domSibling) {
      walk[sp++] = c;
      walk[sp++] = kNone;
    }
  }
}

// Marks live values from the side effects (stores, branches, return).
void RunDce(Fn &f, Arena &ar) {
  const uint32_t words = (f.n + 63) / 64;
  uint64_t *live = ar.Take<uint64_t>(words);
  std::memset(live, 0, words * sizeof(uint64_t));
  uint32_t sp = 0;
  auto mark = [&](uint32_t i) {
    if (i == kNone || IsDead(f.nodes[i]) || (live[i >> 6] >> (i & 63)) & 1) return;
    live[i >> 6] |= 1ull << (i & 63);
    f.stack[sp++] = i;
  };
  for (uint32_t i = f.nconst; i < f.n; ++i)
    if (IsStoreOp(f.nodes[i].op & kOpMask) && !(f.nodes[i].op & (kConstFlag | kPhiFlag | kInputFlag)))
      mark(i);
  for (uint32_t b = 0; b < f.nblocks; ++b) mark(f.blocks[b].cond);
  mark(f.ret);
  while (sp) {
    const Node &n = f.nodes[f.stack[--sp]];
    if (IsConst(n)) continue; // constants have no dependencies
    mark(n.a);
    mark(n.b);
    mark(n.c);
  }
  for (uint32_t i = 0; i < f.n; ++i) {
    if (!((live[i >> 6] >> (i & 63)) & 1) && !IsDead(f.nodes[i])) {
      EraseNode(f, i);
      f.st.dead++;
    }
  }
}
} // namespace simv5
