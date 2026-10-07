// WorkloadRealisticV5Loop.cpp - Realistic V5 loop passes, as in NIR's
// optimization loop: loop analysis (natural loops from back edges whose head
// dominates the latch, preheader, exit, induction variable and trip count of
// counted loops: phi(init, phi + step), compare against a constant bound),
// loop-invariant code motion (pure ALU instructions whose operands are defined
// outside the loop move to the preheader, nir_opt_licm) and full unrolling of
// small single-block counted loops (nir_opt_loop_unroll: the body is cloned
// once per iteration, header phis resolve to the previous iteration's values,
// the back edge disappears and folding finishes the induction variable).
#include "workloads/WorkloadRealisticV5.h"

namespace simv5 {
namespace {
constexpr uint32_t kMaxUnrollIters = 16, kMaxUnrollNodes = 128;

struct Loop {
  uint32_t header, latch, preheader, exit;
};

inline bool Dominates(const Fn &f, uint32_t a, uint32_t b) {
  while (b != a) {
    const uint32_t up = f.blocks[b].idom;
    if (up == b || up == kNone) return false;
    b = up;
  }
  return true;
}

// Blocks of the natural loop latch -> header: reverse reachability from the
// latch without passing the header (marked with the loop's id in `inLoop`).
uint32_t CollectLoop(Fn &f, const Loop &l, uint32_t id, uint32_t *inLoop, uint32_t *work) {
  uint32_t sp = 0, count = 1;
  inLoop[l.header] = id;
  if (inLoop[l.latch] != id) {
    inLoop[l.latch] = id;
    work[sp++] = l.latch;
    count++;
  }
  while (sp) {
    const Block &blk = f.blocks[work[--sp]];
    for (uint32_t p = 0; p < blk.npred; ++p) {
      const uint32_t pb = f.preds[blk.predFirst + p];
      if (inLoop[pb] == id || f.blocks[pb].rpo == kNone) continue;
      inLoop[pb] = id;
      work[sp++] = pb;
      count++;
    }
  }
  return count;
}

// LICM: one sweep over the loop's blocks in RPO; hoisted values count as
// outside, so chains of invariant instructions move together.
uint32_t Hoist(Fn &f, const Loop &l, uint32_t id, const uint32_t *inLoop) {
  uint32_t hoisted = 0;
  const uint32_t pre = l.preheader;
  for (uint32_t k = 0; k < f.nrpo; ++k) {
    const uint32_t b = f.rpoOrder[k];
    if (inLoop[b] != id) continue;
    for (uint32_t i = f.blocks[b].head; i != kNone;) {
      const uint32_t next = f.nodes[i].next;
      const Node &n = f.nodes[i];
      const uint32_t op = OpOf(n);
      bool invariant = IsInst(n) && HasFlag(op, kPure) && !HasFlag(op, kMemRead) && !(n.op & kCondFlag);
      for (uint32_t s = 0, e = invariant ? NumOperands(n) : 0; s < e && invariant; ++s) {
        const Node &o = f.nodes[Operand(n, s)];
        invariant = IsConst(o) || inLoop[o.block] != id;
      }
      if (invariant) {
        Unlink(f, i);
        Node &p = f.nodes[i];
        p.block = pre;
        // Append to the preheader's list (its terminator is implicit).
        uint32_t tail = f.blocks[pre].head;
        if (tail == kNone) {
          f.blocks[pre].head = i;
          p.prev = p.next = kNone;
        } else {
          while (f.nodes[tail].next != kNone) tail = f.nodes[tail].next;
          f.nodes[tail].next = i;
          p.prev = tail;
          p.next = kNone;
        }
        hoisted++;
      }
      i = next;
    }
  }
  return hoisted;
}

// Full unroll of a single-block counted loop with a constant trip count.
bool Unroll(Fn &f, const Loop &l) {
  Block &h = f.blocks[l.header];
  if (l.header != l.latch || h.cond == kNone || h.succ[0] != l.header || h.succ[1] != l.exit) return false;
  // Phis first, then the body; find the induction variable phi(init, iv + 1)
  // and the exit test icmp ult (iv + 1), bound.
  uint32_t nphi = 0, nbody = 0, iv = kNone;
  for (uint32_t i = h.head; i != kNone; i = f.nodes[i].next) {
    if (IsPhi(f.nodes[i])) nphi++;
    else nbody++;
  }
  const Node &c = f.nodes[h.cond];
  if (!IsInst(c) || OpOf(c) != kICmpUlt || !IsConst(f.nodes[c.b])) return false;
  const Node &inext = f.nodes[c.a];
  if (!IsInst(inext) || OpOf(inext) != kIAdd || !IsConst(f.nodes[inext.b]) || f.nodes[inext.b].val != 1) return false;
  iv = inext.a;
  const Node &ivn = f.nodes[iv];
  if (!IsPhi(ivn) || ivn.block != l.header) return false;
  const uint32_t init = f.phiPred[iv] == l.preheader ? ivn.a : ivn.b;
  if (!IsConst(f.nodes[init])) return false;
  const uint32_t bound = (uint32_t)f.nodes[c.b].val;
  uint32_t trip = 0;
  for (uint32_t i = (uint32_t)f.nodes[init].val;; ++i) { // do-while: the body runs before the test
    if (++trip > kMaxUnrollIters) return false;
    if (!(i + 1 < bound)) break;
  }
  if (nbody == 0 || trip * nbody > kMaxUnrollNodes || f.cap - f.n < (trip - 1) * nbody + 32) return false;
  // Per-iteration value maps live in the node's `pos` field (free here) for the
  // current iteration and in a scratch array for phis (prev iteration).
  uint32_t *phiVal = f.stack; // phi values of the current iteration, by phi order
  uint32_t *phis = f.stack + nphi, *body = f.stack + 2 * nphi;
  {
    uint32_t np = 0, nb = 0;
    for (uint32_t i = h.head; i != kNone; i = f.nodes[i].next)
      (IsPhi(f.nodes[i]) ? phis[np++] : body[nb++]) = i;
  }
  uint32_t *map = body + nbody;      // map[k]: copy of body[k] in the current iteration
  uint32_t *orig = map + nbody;      // orig[3k + s]: operand s of body[k] before unrolling
  auto phiIndex = [&](uint32_t v) {
    for (uint32_t p = 0; p < nphi; ++p)
      if (phis[p] == v) return p;
    return kNone;
  };
  auto bodyIndex = [&](uint32_t v) { // SSA in one block: operands precede their users
    const Node &n = f.nodes[v];
    if (IsConst(n) || n.block != l.header || IsPhi(n)) return kNone;
    for (uint32_t k = 0; k < nbody; ++k)
      if (body[k] == v) return k;
    return kNone;
  };
  for (uint32_t p = 0; p < nphi; ++p) {
    const Node &ph = f.nodes[phis[p]];
    phiVal[p] = f.phiPred[phis[p]] == l.preheader ? ph.a : ph.b;
  }
  for (uint32_t k = 0; k < nbody; ++k) {
    const Node &n = f.nodes[body[k]];
    orig[3 * k] = n.a;
    orig[3 * k + 1] = n.b;
    orig[3 * k + 2] = n.c;
  }
  // Iteration 0: the original body reads the initial values.
  for (uint32_t k = 0; k < nbody; ++k) {
    map[k] = body[k];
    for (uint32_t s = 0, e = NumOperands(f.nodes[body[k]]); s < e; ++s) {
      const uint32_t pi = phiIndex(orig[3 * k + s]);
      if (pi != kNone) SetOperand(f, body[k], s, phiVal[pi]);
    }
  }
  uint32_t tail = body[nbody - 1];
  for (uint32_t it = 1; it < trip; ++it) {
    for (uint32_t p = 0; p < nphi; ++p) { // back-edge values of the previous iteration
      const Node &ph = f.nodes[phis[p]];
      const uint32_t back = f.phiPred[phis[p]] == l.preheader ? ph.b : ph.a;
      const uint32_t bk = bodyIndex(back);
      phiVal[p] = bk != kNone ? map[bk] : back;
    }
    for (uint32_t k = 0; k < nbody; ++k) {
      const Node &src = f.nodes[body[k]];
      uint32_t ops[3];
      for (uint32_t s = 0; s < 3; ++s) {
        const uint32_t o = orig[3 * k + s], pi = o == kNone ? kNone : phiIndex(o);
        const uint32_t bk = o == kNone || pi != kNone ? kNone : bodyIndex(o);
        ops[s] = pi != kNone ? phiVal[pi] : bk != kNone ? map[bk] : o;
      }
      const uint32_t x = NewNode(f, src.op & ~(kDivergentFlag | kCondFlag), src.type, ops[0], ops[1], ops[2]);
      if (x == kNone) return false; // not reached: capacity checked above
      Node &xn = f.nodes[x];
      xn.imm = f.nodes[body[k]].imm;
      xn.block = l.header;
      xn.prev = tail;
      xn.next = f.nodes[tail].next;
      if (xn.next != kNone) f.nodes[xn.next].prev = x;
      f.nodes[tail].next = x;
      tail = x;
      map[k] = x;
    }
    f.st.unrolledNodes += nbody;
  }
  // Values used after the loop take the last iteration's copies; the header
  // phis resolve to the last iteration's incoming values.
  for (uint32_t k = 0; k < nbody; ++k) {
    for (uint32_t u = f.nodes[body[k]].firstUse; u != kNone;) {
      const uint32_t next = f.UseNext(u), user = UseUser(u);
      if (f.nodes[user].block != l.header && !IsPhi(f.nodes[user])) SetOperand(f, user, u & 3, map[k]);
      u = next;
    }
  }
  for (uint32_t p = 0; p < nphi; ++p) Replace(f, phis[p], phiVal[p]);
  f.nodes[h.cond].op &= ~kCondFlag;
  h.cond = kNone;
  h.succ[0] = l.exit;
  h.succ[1] = kNone;
  RebuildPreds(f);
  f.st.loopsUnrolled++;
  return true;
}
} // namespace

// Loop analysis + LICM + full unrolling; returns progress. Needs dominators.
bool RunLoopPasses(Fn &f, Arena &ar) {
  const uint32_t nb = f.nblocks;
  uint32_t *inLoop = ar.Take<uint32_t>(nb), *work = ar.Take<uint32_t>(nb);
  if (!inLoop || !work) return false;
  for (uint32_t b = 0; b < nb; ++b) inLoop[b] = kNone;
  bool progress = false;
  uint32_t id = 0;
  for (uint32_t k = 0; k < f.nrpo; ++k) { // latches in RPO: outer loops' latches come last
    const uint32_t lb = f.rpoOrder[k];
    const Block &blk = f.blocks[lb];
    for (uint32_t s : blk.succ) {
      if (s == kNone || f.blocks[s].rpo > blk.rpo || !Dominates(f, s, lb)) continue;
      const Block &hb = f.blocks[s];
      if (hb.npred != 2) continue;
      Loop l{s, lb, kNone, kNone};
      for (uint32_t p = 0; p < 2; ++p)
        if (f.preds[hb.predFirst + p] != lb) l.preheader = f.preds[hb.predFirst + p];
      if (l.preheader == kNone || f.blocks[l.preheader].succ[1] != kNone) continue; // needs a dedicated preheader
      l.exit = blk.succ[0] == s ? blk.succ[1] : blk.succ[0];
      f.st.loops++;
      CollectLoop(f, l, id, inLoop, work);
      const uint32_t h = Hoist(f, l, id, inLoop);
      f.st.licmHoisted += h;
      progress |= h != 0;
      if (l.exit != kNone && Unroll(f, l)) return true; // CFG changed: dominators are stale
      id++;
    }
  }
  return progress;
}
} // namespace simv5
