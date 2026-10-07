// WorkloadRealisticV5IselCf.cpp - Realistic V5 instruction selection of
// control flow (ACO's divergent CF lowering on a structurized CFG):
//  - post-dominators (Cooper-Harvey-Kennedy on the reverse CFG) find the merge
//    of each divergent if; divergent loop latches are back edges whose head
//    dominates the latch;
//  - a divergent if saves exec (s_and_saveexec_b64), skips the then side when
//    no lane takes it (s_cbranch_execz), flips exec to the else lanes in an
//    exec flip block (s_andn2_b64) and restores exec at the merge (s_or_b64);
//    the then side falls into the flip block (linear CFG), so phi copies of
//    both sides run under their lane masks;
//  - a divergent loop saves exec in its preheader, drops exiting lanes at the
//    latch (s_and_b64 exec) and repeats while lanes remain (s_cbranch_execnz);
//    the exit restores exec;
//  - machine layout: split critical edges and flip blocks precede their
//    target; liveness / allocation / waits use the linear CFG, phis the
//    logical predecessors.
#include "workloads/WorkloadRealisticV5Isel.h"

namespace simv5 {
namespace isel {
namespace {
inline bool Dominates(const Fn &f, uint32_t a, uint32_t b) {
  while (b != a) {
    const uint32_t up = f.blocks[b].idom;
    if (up == b || up == kNone) return false;
    b = up;
  }
  return true;
}
inline bool HasPhis(const Fn &f, uint32_t s) {
  return f.blocks[s].head != kNone && IsPhi(f.nodes[f.blocks[s].head]);
}

// Immediate post-dominators; a virtual exit (index nblocks) joins the blocks
// without successors.
void PostDominators(Fn &f, Mach &m) {
  const uint32_t nb = f.nblocks, exit = nb;
  std::vector<uint32_t> &ipd = m.ipdom, &num = m.heap, &order = m.order, &stack = m.scratch2;
  ipd.assign(nb + 1, kNone);
  num.assign(nb + 1, kNone);
  order.clear();
  stack.clear();
  // Reverse-graph DFS from the exit (successors in the reverse graph are CFG
  // predecessors); post order numbers.
  auto revSucc = [&](uint32_t x, uint32_t k) -> uint32_t {
    if (x == exit) { // live blocks without successors
      uint32_t seen = 0;
      for (uint32_t b = 0; b < nb; ++b)
        if (f.blocks[b].rpo != kNone && f.blocks[b].succ[0] == kNone && seen++ == k) return b;
      return kNone;
    }
    const Block &blk = f.blocks[x];
    return k < blk.npred ? f.preds[blk.predFirst + k] : kNone;
  };
  num[exit] = 0x80000000u; // on stack
  stack.push_back(exit);
  stack.push_back(0);
  while (!stack.empty()) {
    const uint32_t k = stack.back(), x = stack[stack.size() - 2];
    const uint32_t s = revSucc(x, k);
    if (s == kNone) {
      stack.resize(stack.size() - 2);
      num[x] = (uint32_t)order.size();
      order.push_back(x);
      continue;
    }
    stack.back() = k + 1;
    if (num[s] == kNone && f.blocks[s].rpo != kNone) {
      num[s] = 0x80000000u;
      stack.push_back(s);
      stack.push_back(0);
    }
  }
  ipd[exit] = exit;
  for (bool changed = true; changed;) {
    changed = false;
    for (uint32_t k = (uint32_t)order.size() - 1; k-- > 0;) { // reverse post order, exit first
      const uint32_t b = order[k];
      const Block &blk = f.blocks[b];
      uint32_t idom = kNone;
      const uint32_t cand[2] = {blk.succ[0] == kNone ? exit : blk.succ[0], blk.succ[1]};
      for (uint32_t c : cand) {
        if (c == kNone || ipd[c] == kNone) continue;
        if (idom == kNone) {
          idom = c;
          continue;
        }
        uint32_t x = c, y = idom;
        while (x != y) {
          while (num[x] < num[y]) x = ipd[x];
          while (num[y] < num[x]) y = ipd[y];
        }
        idom = x;
      }
      if (idom != ipd[b]) {
        ipd[b] = idom;
        changed = true;
      }
    }
  }
}
} // namespace

// Classifies divergent branches (needs dominators, divergence, predecessors).
void Isel::AnalyzeCf() {
  const uint32_t nb = f_.nblocks;
  CfInfo none{};
  none.kind = kCfNone;
  none.merge = none.thenEnd = none.header = none.exit = none.preheader = kNone;
  none.flipBefore = none.teOf = none.flipFor = none.preheaderOf = kNone;
  none.saved = none.restore[0] = none.restore[1] = kONone;
  m_.cf.assign(nb, none);
  PostDominators(f_, m_);
  for (uint32_t b = 0; b < nb; ++b) {
    const Block &blk = f_.blocks[b];
    if (blk.rpo == kNone || blk.cond == kNone || blk.succ[1] == kNone || blk.succ[0] == blk.succ[1]) continue;
    const Node &c = f_.nodes[blk.cond];
    if (IsConst(c) || !(c.op & kDivergentFlag)) continue;
    CfInfo &ci = m_.cf[b];
    const uint32_t s0 = blk.succ[0], s1 = blk.succ[1];
    const bool back0 = f_.blocks[s0].rpo <= blk.rpo, back1 = f_.blocks[s1].rpo <= blk.rpo;
    if (back0 || back1) { // latch of a loop with a divergent exit
      const uint32_t h = back0 ? s0 : s1;
      const Block &hb = f_.blocks[h];
      if (back0 == back1 || !Dominates(f_, h, b) || hb.npred != 2) continue;
      uint32_t pre = kNone;
      for (uint32_t p = 0; p < 2; ++p)
        if (f_.preds[hb.predFirst + p] != b) pre = f_.preds[hb.predFirst + p];
      if (pre == kNone || f_.blocks[pre].succ[1] != kNone || m_.cf[pre].preheaderOf != kNone) continue;
      ci.kind = kCfDivLatch;
      ci.header = h;
      ci.exit = back0 ? s1 : s0;
      ci.preheader = pre;
      m_.cf[pre].preheaderOf = b;
      continue;
    }
    const uint32_t merge = m_.ipdom[b];
    if (merge == kNone || merge >= nb || merge == s0) continue;
    uint32_t te = kNone, count = 0;
    const Block &mb = f_.blocks[merge];
    for (uint32_t p = 0; p < mb.npred; ++p) {
      const uint32_t pb = f_.preds[mb.predFirst + p];
      if (Dominates(f_, s0, pb)) {
        te = pb;
        count++;
      }
    }
    const bool flip = s1 != merge || HasPhis(f_, merge);
    const uint32_t before = s1 != merge ? s1 : merge;
    if (count != 1 || m_.cf[te].teOf != kNone || (flip && m_.cf[before].flipFor != kNone)) continue;
    ci.kind = kCfDivIf;
    ci.flip = flip;
    ci.merge = merge;
    ci.thenEnd = te;
    ci.flipBefore = before;
    if (flip) {
      m_.cf[te].teOf = b;
      m_.cf[before].flipFor = b;
    }
  }
}

void Isel::FlushExports(bool last) {
  uint32_t mask = 0;
  for (uint32_t k = 0; k < 4; ++k) mask |= exports_[k] != kONone ? 1u << k : 0u;
  if (!mask) return;
  const uint32_t mi = Push(m_exp, kONone, exports_[0], exports_[1], exports_[2], exports_[3]);
  code_[mi].imm = (uint16_t)mask; // target mrt0
  code_[mi].flags = last ? kMfDone | kMfVm : 0;
  for (uint32_t &e : exports_) e = kONone;
}

// Machine block of the edge from -> to: the exec flip block after a then side,
// a split critical edge, or `to`.
uint32_t Isel::Target(uint32_t from, uint32_t to) const {
  const uint32_t te = m_.cf[from].teOf;
  if (te != kNone && m_.cf[te].merge == to)
    for (uint32_t k = m_.blockOf[m_.cf[te].flipBefore]; k-- > 0 && m_.blocks[k].ir == kNone;)
      if (m_.blocks[k].flipOf == te) return k;
  for (uint32_t k = m_.blockOf[to]; k-- > 0 && m_.blocks[k].ir == kNone;)
    if (m_.blocks[k].phiFrom[0] == from && m_.blocks[k].phiFrom[1] == to) return k;
  return m_.blockOf[to];
}

uint32_t Isel::ExecOp(uint32_t op, uint32_t a, uint32_t b) { // exec = op(a, b)
  const uint32_t mi = Push(op, kONone, a, b);
  code_[mi].defs[0] = kOFixed | kRegExec;
  code_[mi].ndefs = 1;
  return mi;
}

void Isel::Terminator(uint32_t b) {
  const Block &blk = f_.blocks[b];
  CfInfo &ci = m_.cf[b];
  FlushExports(blk.succ[0] == kNone);
  node_ = kNone;
  if (ci.preheaderOf != kNone) { // divergent loop ahead: remember the entry exec
    const uint32_t saved = NewTemp(kSgpr, 2);
    Push(m_s_mov_b64, saved, kOFixed | kRegExec);
    CfInfo &lc = m_.cf[ci.preheaderOf];
    lc.saved = OTemp(saved);
    CfInfo &xc = m_.cf[lc.exit];
    const uint32_t slot = xc.restore[0] == kONone ? 0 : 1;
    xc.restore[slot] = lc.saved;
    xc.restoreLoop[slot] = 1;
  }
  MBlock &mb = m_.blocks[cur_];
  mb.term = (uint32_t)code_.size();
  const uint32_t next = cur_ + 1;
  auto branch = [&](uint32_t op, uint32_t target) { code_[Push(op, kONone)].aux = target; };
  if (blk.succ[0] == kNone) {
    Push(m_s_endpgm, kONone);
    mb.succ[0] = mb.succ[1] = kNone;
    return;
  }
  const bool two = blk.cond != kNone && blk.succ[1] != kNone;
  if (two && ci.kind == kCfDivIf) {
    const uint32_t mask = Mask(blk.cond);
    mb.term = (uint32_t)code_.size();
    const uint32_t saved = NewTemp(kSgpr, 2);
    const uint32_t mi = Push(m_s_and_saveexec_b64, saved, mask);
    code_[mi].defs[1] = kOFixed | kRegExec;
    code_[mi].ndefs = 2;
    ci.saved = OTemp(saved);
    CfInfo &mc = m_.cf[ci.merge];
    mc.restore[mc.restore[0] == kONone ? 0 : 1] = ci.saved;
    const uint32_t skip = ci.flip ? Target(ci.thenEnd, ci.merge) : m_.blockOf[ci.merge];
    const uint32_t then = Target(b, blk.succ[0]);
    branch(m_s_cbranch_execz, skip);
    mb.succ[0] = then;
    mb.succ[1] = skip;
    if (then != next) branch(m_s_branch, then);
    f_.st.divergentIfs++;
    return;
  }
  if (two && ci.kind == kCfDivLatch && ci.saved != kONone) {
    const uint32_t mask = Mask(blk.cond);
    mb.term = (uint32_t)code_.size();
    const bool contTrue = blk.succ[0] == ci.header;
    ExecOp(contTrue ? m_s_and_b64 : m_s_andn2_b64, kOFixed | kRegExec, mask); // drop exiting lanes
    const uint32_t back = Target(b, ci.header), out = Target(b, ci.exit);
    branch(m_s_cbranch_execnz, back);
    mb.succ[0] = back;
    mb.succ[1] = out;
    if (out != next) branch(m_s_branch, out);
    f_.st.divergentLoops++;
    return;
  }
  if (two && !IsConst(f_.nodes[blk.cond])) {
    const uint32_t tt = Target(b, blk.succ[0]), tf = Target(b, blk.succ[1]);
    if (f_.nodes[blk.cond].op & kDivergentFlag) f_.st.cfFallback++; // unstructured: any active lane
    Scc(Val(blk.cond));
    branch(m_s_cbranch_scc1, tt);
    mb.succ[0] = tt;
    mb.succ[1] = tf;
    if (tf != next) branch(m_s_branch, tf);
    return;
  }
  const uint32_t to = two && !(f_.nodes[blk.cond].val & 1) ? blk.succ[1] : blk.succ[0];
  const uint32_t tgt = Target(b, to);
  mb.succ[0] = tgt;
  mb.succ[1] = kNone;
  if (tgt != next) branch(m_s_branch, tgt);
}

// Machine block layout: IR blocks in order; exec flip blocks and split
// critical edges into phi blocks precede their target.
void Isel::Layout() {
  m_.blocks.clear();
  m_.blockOf.assign(f_.nblocks, kNone);
  auto add = [&](uint32_t ir, uint32_t from, uint32_t to, uint32_t flipOf) {
    MBlock mb{};
    mb.ir = ir;
    mb.succ[0] = mb.succ[1] = kNone;
    mb.phiFrom[0] = from;
    mb.phiFrom[1] = to;
    mb.flipOf = flipOf;
    m_.blocks.push_back(mb);
  };
  for (uint32_t b = 0; b < f_.nblocks; ++b) {
    const Block &blk = f_.blocks[b];
    if (blk.rpo == kNone) continue;
    if (m_.cf[b].flipFor != kNone) add(kNone, kNone, kNone, m_.cf[b].flipFor);
    if (HasPhis(f_, b) && blk.npred >= 2)
      for (uint32_t p = 0; p < blk.npred; ++p) {
        const uint32_t pb = f_.preds[blk.predFirst + p];
        const Block &pk = f_.blocks[pb];
        if (pk.cond != kNone && pk.succ[1] != kNone && !IsConst(f_.nodes[pk.cond])) add(kNone, pb, b, kNone);
      }
    m_.blockOf[b] = (uint32_t)m_.blocks.size();
    add(b, kNone, kNone, kNone);
  }
}

void Isel::Run() {
  code_.clear();
  m_.temps.clear();
  m_.scratch.clear();
  for (uint32_t i = 0; i < f_.n; ++i) f_.nodes[i].reg = kONone;
  for (uint32_t i = 0; i < f_.n && !compute_; ++i)
    compute_ = IsInst(f_.nodes[i]) && !IsDead(f_.nodes[i]) &&
               (OpOf(f_.nodes[i]) == kThreadId || OpOf(f_.nodes[i]) == kGroupId);
  AnalyzeCf();
  Layout();
  std::vector<uint32_t> &phis = m_.work;
  phis.clear();
  for (uint32_t mbi = 0; mbi < m_.blocks.size(); ++mbi) {
    MBlock &mb = m_.blocks[mbi];
    cur_ = mbi;
    sampMap_.Clear();
    descMap_.Clear();
    mb.start = (uint32_t)code_.size();
    node_ = kNone;
    if (mb.flipOf != kNone) { // else lanes: exec = saved & ~exec, skip when none
      const CfInfo &ci = m_.cf[mb.flipOf];
      ExecOp(m_s_andn2_b64, ci.saved, kOFixed | kRegExec);
      mb.term = (uint32_t)code_.size();
      const uint32_t merge = m_.blockOf[ci.merge];
      code_[Push(m_s_cbranch_execz, kONone)].aux = merge;
      mb.succ[0] = mbi + 1;
      mb.succ[1] = merge;
      mb.end = (uint32_t)code_.size();
      continue;
    }
    if (mb.ir == kNone) { // split edge: phi copies (LowerToHw) + branch
      mb.term = mb.start;
      const uint32_t to = m_.blockOf[mb.phiFrom[1]];
      mb.succ[0] = to;
      if (to != mbi + 1) code_[Push(m_s_branch, kONone)].aux = to;
      mb.end = (uint32_t)code_.size();
      continue;
    }
    if (mbi == 0) { // shader inputs (user SGPRs, VGPR inputs), M0 for interpolation
      auto input = [&](uint8_t cls, uint8_t size, uint32_t reg) {
        const uint32_t t = NewTemp(cls, size);
        m_.temps[t].fixed = reg;
        code_[Push(m_p_startpgm, t)].imm = (uint16_t)reg;
        return OTemp(t);
      };
      desc_ = input(kSgpr, 2, 0);
      prim_ = grp_ = input(kSgpr, 1, 2);
      for (uint32_t k = 0; k < (compute_ ? 3u : 2u); ++k) tid_[k] = input(kVgpr, 1, kRegVgpr + k);
      bary_[0] = tid_[0];
      bary_[1] = tid_[1];
      if (!compute_) {
        const uint32_t mi = Push(m_s_mov_b32, kONone, prim_);
        code_[mi].defs[0] = kOFixed | kRegM0;
        code_[mi].ndefs = 1;
      }
    }
    bool restored = false;
    auto restore = [&] { // exec back to the lanes before the divergent region
      restored = true;
      const CfInfo &ci = m_.cf[mb.ir];
      for (uint32_t k = 0; k < 2; ++k) {
        if (ci.restore[k] == kONone) continue;
        if (ci.restoreLoop[k]) {
          const uint32_t mi = Push(m_s_mov_b64, kONone, ci.restore[k]);
          code_[mi].defs[0] = kOFixed | kRegExec;
          code_[mi].ndefs = 1;
        } else {
          ExecOp(m_s_or_b64, kOFixed | kRegExec, ci.restore[k]);
        }
      }
    };
    for (uint32_t i = f_.blocks[mb.ir].head; i != kNone; i = f_.nodes[i].next) {
      Node &n = f_.nodes[i];
      if (IsPhi(n)) {
        const Cls c = ClassOf(i);
        const uint32_t d = NewTemp(c.cls, c.size);
        node_ = i;
        Push(m_p_phi, d);
        n.reg = OTemp(d);
        phis.push_back((uint32_t)code_.size() - 1);
        continue;
      }
      if (!restored) restore();
      SelectNode(i);
    }
    if (!restored) restore();
    Terminator(mb.ir);
    m_.blocks[cur_].end = (uint32_t)code_.size();
  }
  // Linear predecessors from the successor edges; logical predecessors (phi
  // operand order) from the IR edges, through split edges.
  for (MBlock &mb : m_.blocks) mb.npred = mb.nlpred = 0;
  for (uint32_t b = 0; b < m_.blocks.size(); ++b)
    for (uint32_t s : m_.blocks[b].succ) {
      if (s == kNone) continue;
      MBlock &sb = m_.blocks[s];
      if (sb.npred < 4) sb.pred[sb.npred++] = b;
      else f_.st.machErrors++;
    }
  for (uint32_t b = 0; b < f_.nblocks; ++b) {
    if (m_.blockOf[b] == kNone) continue;
    MBlock &sb = m_.blocks[m_.blockOf[b]];
    const Block &blk = f_.blocks[b];
    for (uint32_t p = 0; p < blk.npred && sb.nlpred < 2; ++p) {
      const uint32_t pb = f_.preds[blk.predFirst + p];
      if (m_.blockOf[pb] == kNone) continue;
      uint32_t lp = m_.blockOf[pb];
      for (uint32_t k = m_.blockOf[b]; k-- > 0 && m_.blocks[k].ir == kNone;)
        if (m_.blocks[k].phiFrom[0] == pb && m_.blocks[k].phiFrom[1] == b) lp = k;
      sb.lpred[sb.nlpred++] = lp;
    }
  }
  for (uint32_t pi : phis) { // code_ indexed per access: Val may append instructions
    const uint32_t node = code_[pi].node, blk = code_[pi].block;
    const Node &n = f_.nodes[node];
    const uint32_t np = m_.blocks[blk].nlpred;
    for (uint32_t k = 0; k < np; ++k) {
      const MBlock &p = m_.blocks[m_.blocks[blk].lpred[k]];
      const uint32_t irPred = p.ir == kNone ? p.phiFrom[0] : p.ir;
      const uint32_t o = Val(f_.phiPred[node] == irPred ? n.a : n.b);
      code_[pi].ops[k] = o;
      if (IsTempOp(o)) m_.temps[TempOf(o)].uses++;
    }
    code_[pi].nops = (uint8_t)np;
  }
  f_.st.literals += m_.scratch.size();
}
} // namespace isel

void SelectInstructions(Fn &f, Mach &m) {
  isel::Isel sel(f, m);
  sel.Run();
}
} // namespace simv5
