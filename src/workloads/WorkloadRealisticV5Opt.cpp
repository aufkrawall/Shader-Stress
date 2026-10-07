// WorkloadRealisticV5Opt.cpp - Realistic V5 middle end: value replacement,
// dead control flow (nir_opt_dead_cf / SimplifyCFG), dominator tree, scoped
// dominator-tree CSE (EarlyCSE / nir_opt_cse) and DCE. Folding and algebraic
// rules live in WorkloadRealisticV5Fold.cpp.
#include "workloads/WorkloadRealisticV5.h"
#include <cstdio>

namespace simv5 {
// The instruction folds to a constant: it leaves the instruction list (its
// users keep referring to the node, now a constant of the same type).
void MakeConst(Fn &f, uint32_t i, uint64_t bits) {
  DropOperands(f, i);
  Unlink(f, i);
  Node &n = f.nodes[i];
  n.op = kConstFlag | kNotAnOp | (n.op & kCondFlag);
  n.val = bits;
  MapConst(f, i);
}

// Replace all uses of `from` with `to` (`to` dominates `from`; LLVM
// replaceAllUsesWith), splice the use list over and erase `from`. Terminator
// operands follow the replacement.
void Replace(Fn &f, uint32_t from, uint32_t to) {
  Node &n = f.nodes[from];
  uint32_t last = kNone;
  for (uint32_t u = n.firstUse; u != kNone; u = f.UseNext(u)) {
    OperandRef(f.nodes[UseUser(u)], u & 3) = to;
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
    f.nodes[to].op |= kCondFlag;
    n.op &= ~kCondFlag;
  }
  n.firstUse = kNone;
  n.numUses = 0;
  EraseNode(f, from);
}

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
  for (uint32_t i = f.blocks[s].head; i != kNone && IsPhi(f.nodes[i]);) {
    const uint32_t next = f.nodes[i].next;
    const Node &p = f.nodes[i];
    const uint32_t other = f.phiPred[i] == pred ? p.b : p.a;
    const Node &o = f.nodes[other];
    if (other != i && (IsConst(o) || f.blocks[o.block].rpo < f.blocks[s].rpo)) { // not a back-edge value
      f.st.peepholes++;
      Replace(f, i, other);
    }
    i = next;
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
    if (reach[b] || (blk.succ[0] == kNone && blk.head == kNone)) continue;
    for (uint32_t s : blk.succ)
      if (s != kNone && reach[s]) RemovePhiEdge(f, s, b);
    while (blk.head != kNone) { // erase the block's instructions
#ifdef SIMV5_DEAD_TRACE
      if (f.diag) std::fprintf(stderr, "deadop cf %u%c", IsPhi(f.nodes[blk.head]) ? 999u : OpOf(f.nodes[blk.head]), 10);
#endif
      EraseNode(f, blk.head);
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
bool RunCse(Fn &f, Arena &ar) {
  const uint64_t hitsBefore = f.st.cseHits;
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
    for (uint32_t i = f.blocks[b].head, next; i != kNone; i = next) {
      next = f.nodes[i].next;
      const Node &n = f.nodes[i];
      if (!IsInst(n) || !HasFlag(OpOf(n), kPure)) continue;
      const uint32_t op = OpOf(n);
      uint64_t h = OpConst(op, n.a) ^ ((uint64_t)n.b << 21) ^ ((uint64_t)n.c << 42) ^ ((uint64_t)n.imm << 61);
      h ^= h >> 29;
      for (uint32_t s = (uint32_t)h & (size - 1);; s = (s + 1) & (size - 1)) {
        if (table[s] == 0) {
          table[s] = i + 1;
          undo[nundo++] = s;
          break;
        }
        const Node &m = f.nodes[table[s] - 1];
        if (OpOf(m) == op && m.type == n.type && m.a == n.a && m.b == n.b && m.c == n.c && m.imm == n.imm) {
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
  return f.st.cseHits != hitsBefore;
}

// Marks live values from the side effects (stores, outputs, branches).
bool RunDce(Fn &f, Arena &ar) {
  const uint64_t deadBefore = f.st.dead;
  const uint32_t words = (f.n + 63) / 64;
  uint64_t *live = ar.Take<uint64_t>(words);
  std::memset(live, 0, words * sizeof(uint64_t));
  uint32_t sp = 0;
  auto mark = [&](uint32_t i) {
    if (i == kNone || IsDead(f.nodes[i]) || (live[i >> 6] >> (i & 63)) & 1) return;
    live[i >> 6] |= 1ull << (i & 63);
    f.stack[sp++] = i;
  };
  for (uint32_t i = 0; i < f.n; ++i)
    if (IsStore(f.nodes[i]) && !IsDead(f.nodes[i])) mark(i);
  for (uint32_t b = 0; b < f.nblocks; ++b) mark(f.blocks[b].cond);
  while (sp) {
    const Node &n = f.nodes[f.stack[--sp]];
    if (IsConst(n)) continue; // constants have no dependencies
    mark(n.a);
    mark(n.b);
    mark(n.c);
  }
  for (uint32_t i = 0; i < f.n; ++i) { // constants stay: the uniquing map owns them
    if (!((live[i >> 6] >> (i & 63)) & 1) && !IsDead(f.nodes[i]) && !IsConst(f.nodes[i])) {
#ifdef SIMV5_DEAD_TRACE
      if (f.diag) std::fprintf(stderr, "deadop dce %u%c", IsPhi(f.nodes[i]) ? 999u : OpOf(f.nodes[i]), 10);
#endif
      EraseNode(f, i);
      f.st.dead++;
    }
  }
  return f.st.dead != deadBefore;
}
} // namespace simv5
