// WorkloadRealisticV5Ra.cpp - Realistic V5 machine liveness, register
// allocation and lowering of pseudo instructions (ACO live_var_analysis,
// register_allocation and lower_to_hw_instr in spirit): dense-bitset block
// liveness over temporaries with phi operands live out of their machine
// predecessor, single-interval linear scan per register file with dword
// alignment, precolored shader inputs, phi affinity hints and kill reuse,
// then phis become parallel copies at the end of each predecessor (critical
// edges were split at selection), sequenced with swap cycles.
#include "workloads/WorkloadRealisticV5Mach.h"
#include <algorithm>

namespace simv5 {
namespace {
inline void SetB(uint64_t *s, uint32_t k) { s[k >> 6] |= 1ull << (k & 63); }
inline void ClrB(uint64_t *s, uint32_t k) { s[k >> 6] &= ~(1ull << (k & 63)); }

void Liveness(Fn &f, Mach &m) {
  const uint32_t nt = (uint32_t)m.temps.size(), nb = (uint32_t)m.blocks.size();
  const uint32_t words = std::max(1u, (nt + 63) / 64);
  m.liveWords = words;
  m.liveIn.assign((size_t)nb * words, 0);
  m.liveOut.assign((size_t)nb * words, 0);
  m.live.resize(words);
  m.order.resize(nb);
  m.heap.assign(nb, 0); // queued flags
  // Phi operands are live out of the logical predecessor (copies run there).
  m.phiUseFirst.assign(nb + 1, 0);
  auto forPhiOps = [&](auto &&body) {
    for (uint32_t s = 0; s < nb; ++s) {
      const MBlock &sb = m.blocks[s];
      for (uint32_t i = sb.start; i < sb.end && m.code[i].op == m_p_phi; ++i)
        for (uint32_t k = 0; k < m.code[i].nops && k < sb.nlpred; ++k)
          if (IsTempOp(m.code[i].ops[k])) body(sb.lpred[k], TempOf(m.code[i].ops[k]));
    }
  };
  forPhiOps([&](uint32_t p, uint32_t) { m.phiUseFirst[p + 1]++; });
  for (uint32_t b = 0; b < nb; ++b) m.phiUseFirst[b + 1] += m.phiUseFirst[b];
  m.phiUse.resize(m.phiUseFirst[nb]);
  m.order.assign(m.phiUseFirst.begin(), m.phiUseFirst.end() - 1); // fill cursors
  forPhiOps([&](uint32_t p, uint32_t t) { m.phiUse[m.order[p]++] = t; });
  m.order.resize(nb);
  uint32_t sp = 0;
  for (uint32_t b = 0; b < nb; ++b) { // pops in reverse layout order
    m.order[sp++] = b;
    m.heap[b] = 1;
  }
  uint64_t *live = m.live.data();
  while (sp) {
    const uint32_t b = m.order[--sp];
    m.heap[b] = 0;
    f.st.liveVisits++;
    const MBlock &mb = m.blocks[b];
    std::fill(live, live + words, 0);
    for (uint32_t s : mb.succ) { // linear successors
      if (s == kNone) continue;
      const uint64_t *in = &m.liveIn[(size_t)s * words];
      for (uint32_t w = 0; w < words; ++w) live[w] |= in[w];
    }
    for (uint32_t k = m.phiUseFirst[b]; k < m.phiUseFirst[b + 1]; ++k) SetB(live, m.phiUse[k]);
    std::copy(live, live + words, &m.liveOut[(size_t)b * words]);
    for (uint32_t i = mb.end; i-- > mb.start;) {
      const MInst &mi = m.code[i];
      for (uint32_t d = 0; d < mi.ndefs; ++d)
        if (IsTempOp(mi.defs[d])) ClrB(live, TempOf(mi.defs[d]));
      if (mi.op == m_p_phi) continue;
      for (uint32_t k = 0; k < mi.nops; ++k)
        if (IsTempOp(mi.ops[k])) SetB(live, TempOf(mi.ops[k]));
    }
    uint64_t *in = &m.liveIn[(size_t)b * words];
    if (!std::equal(live, live + words, in)) {
      std::copy(live, live + words, in);
      for (uint32_t p = 0; p < mb.npred; ++p)
        if (!m.heap[mb.pred[p]]) {
          m.heap[mb.pred[p]] = 1;
          m.order[sp++] = mb.pred[p];
        }
    }
  }
  f.st.liveBits += (uint64_t)nb * words * 64;
}

// Register file bitmaps: SGPR codes 0..127, VGPR 0..255.
struct Files {
  uint64_t s[2], v[4];
  bool Free(uint8_t cls, uint32_t r, uint32_t size) const {
    const uint64_t *w = cls == kSgpr ? s : v;
    for (uint32_t k = r; k < r + size; ++k)
      if ((w[k >> 6] >> (k & 63)) & 1) return false;
    return true;
  }
  void Mark(uint8_t cls, uint32_t r, uint32_t size, bool busy) {
    uint64_t *w = cls == kSgpr ? s : v;
    for (uint32_t k = r; k < r + size; ++k) {
      if (busy) w[k >> 6] |= 1ull << (k & 63);
      else w[k >> 6] &= ~(1ull << (k & 63));
    }
  }
};

void PushHeap(std::vector<uint32_t> &h, uint32_t &n, const std::vector<MTemp> &t, uint32_t x) {
  if (h.size() <= n) h.resize(n + 64);
  uint32_t k = n++;
  h[k] = x;
  while (k && t[h[(k - 1) / 2]].end > t[h[k]].end) {
    std::swap(h[(k - 1) / 2], h[k]);
    k = (k - 1) / 2;
  }
}
uint32_t PopHeap(std::vector<uint32_t> &h, uint32_t &n, const std::vector<MTemp> &t) {
  const uint32_t top = h[0];
  h[0] = h[--n];
  for (uint32_t k = 0;;) {
    uint32_t c = 2 * k + 1;
    if (c >= n) break;
    if (c + 1 < n && t[h[c + 1]].end < t[h[c]].end) ++c;
    if (t[h[k]].end <= t[h[c]].end) break;
    std::swap(h[k], h[c]);
    k = c;
  }
  return top;
}

uint16_t Code(const Mach &m, uint32_t o, uint32_t &literal) {
  if (o == kONone) return 0;
  switch (o & kOKind) {
  case kOInline: return (uint16_t)(o & 0x1FF);
  case kOLit: literal = m.scratch[o & ~kOKind]; return 255;
  case kOFixed: return (uint16_t)(o & 0x3FF);
  default: {
    const MTemp &t = m.temps[TempOf(o)];
    return t.phys == kPhysSpill ? (t.cls == kVgpr ? kRegVgpr : 0) : (uint16_t)(t.phys + SubOf(o));
  }
  }
}
} // namespace

void AllocateRegisters(Fn &f, Mach &m) {
  Liveness(f, m);
  const uint32_t nt = (uint32_t)m.temps.size(), words = m.liveWords;
  // Intervals: definition to last use; live-out extends to the block end.
  for (uint32_t t = 0; t < nt; ++t) {
    MTemp &x = m.temps[t];
    x.start = x.end = x.def == kNone ? 0 : x.def;
    x.pad = 0;
  }
  for (uint32_t b = 0; b < m.blocks.size(); ++b) {
    const MBlock &mb = m.blocks[b];
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      const MInst &mi = m.code[i];
      if (mi.op == m_p_phi) {
        if (IsTempOp(mi.defs[0])) m.temps[TempOf(mi.defs[0])].start = mb.start;
        continue;
      }
      for (uint32_t k = 0; k < mi.nops; ++k)
        if (IsTempOp(mi.ops[k])) {
          MTemp &x = m.temps[TempOf(mi.ops[k])];
          x.end = std::max(x.end, i);
        }
    }
    const uint64_t *out = &m.liveOut[(size_t)b * words];
    const uint32_t last = mb.end ? mb.end - 1 : 0;
    for (uint32_t w = 0; w < words; ++w)
      for (uint64_t bits = out[w]; bits; bits &= bits - 1) {
        MTemp &x = m.temps[w * 64 + (uint32_t)std::countr_zero(bits)];
        x.end = std::max(x.end, last);
      }
  }
  // Phi affinity: a phi and its operands prefer one register (no copy).
  for (const MInst &mi : m.code) {
    if (mi.op != m_p_phi || !IsTempOp(mi.defs[0])) continue;
    for (uint32_t k = 0; k < mi.nops; ++k)
      if (IsTempOp(mi.ops[k])) {
        m.temps[TempOf(mi.ops[k])].hint = TempOf(mi.defs[0]) | 0x80000000u; // back edges
        if (m.temps[TempOf(mi.defs[0])].hint == kNone) // forward edges
          m.temps[TempOf(mi.defs[0])].hint = TempOf(mi.ops[k]) | 0x80000000u;
      }
  }
  Files files{};
  files.Mark(kSgpr, kSgprScratch, 128 - kSgprScratch, true); // scratch, flat_scratch, xnack, vcc, m0, exec, ...
  uint32_t nactive = 0;
  m.sgprs = m.vgprs = 0;
  auto release = [&](uint32_t t) {
    MTemp &x = m.temps[t];
    if (x.pad || x.phys == kPhysSpill) return;
    x.pad = 1;
    files.Mark(x.cls, x.cls == kSgpr ? x.phys : x.phys - kRegVgpr, x.size, false);
  };
  auto allocate = [&](uint32_t t) {
    MTemp &x = m.temps[t];
    const uint32_t limit = x.cls == kSgpr ? kSgprScratch : kVgprs, base = x.cls == kSgpr ? 0 : kRegVgpr;
    const uint32_t align = x.cls == kSgpr ? (x.size >= 4 ? 4 : x.size) : 1;
    uint32_t r = kNone;
    if (x.fixed != kNone) r = x.fixed - base;
    if (r == kNone && x.hint != kNone) {
      const MTemp &ht = m.temps[x.hint & kTempMask];
      const uint32_t h = !(x.hint & 0x80000000u) ? x.hint
                         : ht.phys == kPhysSpill ? kPhysSpill : ht.phys + ((x.hint >> 24) & 0x3F);
      if (h != kPhysSpill && h >= base && h - base + x.size <= limit && files.Free(x.cls, h - base, x.size)) r = h - base;
    }
    for (uint32_t c = 0; r == kNone && c + x.size <= limit; c += align)
      if (files.Free(x.cls, c, x.size)) r = c;
    if (r == kNone) {
      x.phys = kPhysSpill;
      f.st.spills++;
      return;
    }
    files.Mark(x.cls, r, x.size, true);
    x.phys = (uint16_t)(base + r);
    if (x.cls == kSgpr) m.sgprs = std::max(m.sgprs, r + x.size);
    else m.vgprs = std::max(m.vgprs, r + x.size);
    PushHeap(m.heap, nactive, m.temps, t);
  };
  for (uint32_t i = 0; i < m.code.size(); ++i) {
    while (nactive && m.temps[m.heap[0]].end < i) release(PopHeap(m.heap, nactive, m.temps));
    MInst &mi = m.code[i];
    if (mi.op != m_p_phi) // operands killed here: their registers serve this instruction's results
      for (uint32_t k = 0; k < mi.nops; ++k)
        if (IsTempOp(mi.ops[k]) && m.temps[TempOf(mi.ops[k])].end == i)
          release(TempOf(mi.ops[k]));
    for (uint32_t d = 0; d < mi.ndefs; ++d)
      if (IsTempOp(mi.defs[d])) {
        const uint32_t t = TempOf(mi.defs[d]);
        if (m.temps[t].start == i || mi.op == m_p_phi) allocate(t);
      }
  }
  // Register codes into the instructions.
  for (MInst &mi : m.code) {
    uint32_t lit = 0;
    for (uint32_t d = 0; d < 2; ++d) mi.pdef[d] = Code(m, mi.defs[d], lit);
    for (uint32_t k = 0; k < 4; ++k) mi.pop[k] = Code(m, mi.ops[k], lit);
    mi.literal = lit;
  }
}

namespace {
struct Copy {
  uint16_t dst, src;
  uint8_t size, srcKind; // srcKind: 0 register, 1 constant
  uint32_t lit;
};
inline bool Overlap(uint32_t a, uint32_t as, uint32_t b, uint32_t bs) { return a < b + bs && b < a + as; }

class HwLowering {
public:
  HwLowering(Fn &f, Mach &m) : f_(f), m_(m), out_(m.tmp) {}
  void Run();

private:
  void Mov(uint32_t dst, uint32_t src, uint32_t size, uint32_t lit) {
    MInst mi;
    std::memset(&mi, 0xFF, sizeof(mi));
    const bool v = dst >= kRegVgpr;
    mi.op = (uint16_t)(v ? m_v_mov_b32 : size == 2 ? m_s_mov_b64 : m_s_mov_b32);
    mi.nops = mi.ndefs = 1; // physical operands (allocation is done)
    mi.defs[0] = kOFixed | dst;
    mi.defs[1] = kONone;
    mi.ops[0] = kOFixed | src;
    mi.ops[1] = mi.ops[2] = mi.ops[3] = kONone;
    mi.mods = mi.flags = 0;
    mi.imm = 0;
    mi.pdef[0] = (uint16_t)dst;
    mi.pdef[1] = 0;
    mi.pop[0] = (uint16_t)src;
    mi.pop[1] = mi.pop[2] = mi.pop[3] = 0;
    mi.literal = lit;
    mi.block = block_;
    mi.node = kNone;
    mi.aux = kNone;
    out_.push_back(mi);
    f_.st.copies++;
  }
  void Swap(uint32_t a, uint32_t b, uint32_t size) {
    if (a >= kRegVgpr) {
      Mov(a, b, 1, 0);
      out_.back().op = m_v_swap_b32; // v_swap_b32 a, b
      return;
    }
    for (int k = 0; k < 3; ++k) { // s_xor swap
      Mov(k == 1 ? b : a, k == 1 ? a : b, size, 0);
      MInst &mi = out_.back();
      mi.op = (uint16_t)(size == 2 ? m_s_xor_b64 : m_s_xor_b32);
      mi.pop[1] = mi.pdef[0];
      mi.ops[1] = kOFixed | mi.pdef[0];
      mi.nops = 2;
    }
  }
  void Sequence(Copy *c, uint32_t n);
  Fn &f_;
  Mach &m_;
  std::vector<MInst> &out_;
  uint32_t block_ = 0;
};

// Parallel copy: emit a move once no pending copy still reads its
// destination; cycles are broken with swaps; constants come last.
void HwLowering::Sequence(Copy *c, uint32_t n) {
  uint32_t live = 0;
  for (uint32_t k = 0; k < n; ++k)
    if (c[k].srcKind || c[k].dst != c[k].src) c[live++] = c[k];
  n = live;
  while (n) {
    uint32_t pick = kNone;
    for (uint32_t k = 0; k < n && pick == kNone; ++k) {
      if (c[k].srcKind) continue;
      bool blocked = false;
      for (uint32_t j = 0; j < n && !blocked; ++j)
        blocked = j != k && !c[j].srcKind && Overlap(c[k].dst, c[k].size, c[j].src, c[j].size);
      if (!blocked) pick = k;
    }
    if (pick == kNone) { // every register copy waits: follow the chain into a cycle
      uint32_t k = 0;
      while (k < n && c[k].srcKind) ++k;
      if (k == n) break; // only constants left
      for (uint32_t steps = 0; steps < n; ++steps) {
        uint32_t next = kNone;
        for (uint32_t j = 0; j < n && next == kNone; ++j)
          if (j != k && !c[j].srcKind && c[j].src == c[k].dst) next = j;
        if (next == kNone) break;
        k = next;
      }
      const Copy x = c[k];
      Swap(x.dst, x.src, x.size); // dst now holds src's value and src holds dst's
      for (uint32_t j = 0; j < n; ++j) {
        if (j == k || c[j].srcKind) continue;
        if (c[j].src == x.dst) c[j].src = x.src;
        else if (c[j].src == x.src) c[j].src = x.dst;
      }
      c[k] = c[--n];
      f_.st.swaps++;
      continue;
    }
    Mov(c[pick].dst, c[pick].src, c[pick].size, 0);
    c[pick] = c[--n];
  }
  for (uint32_t k = 0; k < n; ++k) Mov(c[k].dst, c[k].src, c[k].size, c[k].lit);
}

void HwLowering::Run() {
  out_.clear();
  const uint32_t nb = (uint32_t)m_.blocks.size();
  // Phi copies bucketed by predecessor (counting sort).
  std::vector<uint32_t> &first = m_.order, &cw = m_.work;
  first.assign(nb + 1, 0);
  auto forPhis = [&](auto &&body) {
    for (uint32_t s = 0; s < nb; ++s) {
      const MBlock &sb = m_.blocks[s];
      for (uint32_t i = sb.start; i < sb.end && m_.code[i].op == m_p_phi; ++i)
        for (uint32_t k = 0; k < m_.code[i].nops && k < sb.nlpred; ++k) body(sb.lpred[k], m_.code[i], k);
    }
  };
  forPhis([&](uint32_t p, const MInst &, uint32_t) { first[p + 1]++; });
  for (uint32_t b = 0; b < nb; ++b) first[b + 1] += first[b];
  cw.assign((size_t)first[nb] * 3, 0);
  std::vector<uint32_t> fill(first.begin(), first.end() - 1);
  forPhis([&](uint32_t p, const MInst &mi, uint32_t k) {
    const uint32_t at = fill[p]++;
    const MTemp &t = m_.temps[TempOf(mi.defs[0])];
    cw[at * 3] = mi.pdef[0] | (uint32_t)mi.pop[k] << 16;
    cw[at * 3 + 1] = t.size | (IsTempOp(mi.ops[k]) ? 0 : 0x100);
    cw[at * 3 + 2] = (mi.ops[k] & kOKind) == kOLit ? m_.scratch[mi.ops[k] & ~kOKind] : 0;
  });
  Copy pc[64];
  auto flushPhis = [&](uint32_t b) {
    for (uint32_t at = first[b]; at < first[b + 1];) {
      uint32_t n = 0;
      for (; at < first[b + 1] && n < 64; ++at, ++n)
        pc[n] = {(uint16_t)(cw[at * 3] & 0xFFFF), (uint16_t)(cw[at * 3] >> 16), (uint8_t)(cw[at * 3 + 1] & 0xFF),
                 (uint8_t)(cw[at * 3 + 1] >> 8), cw[at * 3 + 2]};
      Sequence(pc, n);
    }
  };
  for (uint32_t b = 0; b < nb; ++b) {
    MBlock &mb = m_.blocks[b];
    block_ = b;
    const uint32_t start = (uint32_t)out_.size();
    uint32_t term = kNone;
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      if (i == mb.term) {
        flushPhis(b);
        term = (uint32_t)out_.size();
      }
      const MInst &mi = m_.code[i];
      switch (mi.op) {
      case m_p_startpgm: case m_p_phi: break;
      case m_p_create_vector: {
        uint32_t n = 0;
        for (uint32_t k = 0; k < mi.nops; ++k)
          pc[n++] = {(uint16_t)(mi.pdef[0] + k), mi.pop[k], 1, (uint8_t)(IsTempOp(mi.ops[k]) ? 0 : 1),
                     (mi.ops[k] & kOKind) == kOLit ? m_.scratch[mi.ops[k] & ~kOKind] : 0};
        Sequence(pc, n);
        break;
      }
      default:
        if ((mi.op == m_s_mov_b32 || mi.op == m_v_mov_b32) && mi.pdef[0] == mi.pop[0] && IsTempOp(mi.ops[0])) {
          f_.st.copiesCoalesced++;
          break; // coalesced copy
        }
        out_.push_back(mi);
        if (mi.op == m_v_mad_f32 && !mi.mods && mi.pdef[0] == mi.pop[2] && mi.pop[1] >= kRegVgpr &&
            mi.pop[2] >= kRegVgpr) { // v_mac_f32: dst is the addend (VOP2)
          MInst &mac = out_.back();
          mac.op = m_v_mac_f32;
          mac.ops[2] = kONone;
          mac.nops = 2;
          f_.st.macConverted++;
        }
      }
    }
    if (term == kNone) {
      flushPhis(b);
      term = (uint32_t)out_.size();
    }
    mb.start = start;
    mb.term = term;
    mb.end = (uint32_t)out_.size();
  }
  m_.code.swap(out_);
}
} // namespace

void LowerToHw(Fn &f, Mach &m) {
  HwLowering lower(f, m);
  lower.Run();
}

// Diagnostic checks of the selected machine code (temporaries defined before
// use in their block, register-class rules, phi operand counts).
uint32_t ValidateMachine(const Fn &f, const Mach &m) {
  (void)f;
  uint32_t errors = 0;
  const uint32_t nt = (uint32_t)m.temps.size();
  for (uint32_t b = 0; b < m.blocks.size(); ++b) {
    const MBlock &mb = m.blocks[b];
    if (mb.start > mb.term || mb.term > mb.end || (b && mb.start != m.blocks[b - 1].end)) errors++;
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      const MInst &mi = m.code[i];
      if (mi.op == m_p_phi && mi.nops != mb.nlpred) errors++;
      for (uint32_t k = mi.nops; k < 4; ++k) // operands beyond nops would be invisible to liveness
        if (mi.ops[k] != kONone) errors++;
      for (uint32_t k = 0; k < mi.nops; ++k) {
        if (!IsTempOp(mi.ops[k])) continue;
        const uint32_t t = TempOf(mi.ops[k]);
        if (t >= nt || m.temps[t].def == kNone) { errors++; continue; }
        const MTemp &x = m.temps[t];
        const uint32_t dblk = m.code[x.def].block;
        if (mi.op != m_p_phi && dblk == b && x.def >= i) errors++;
        if (SubOf(mi.ops[k]) >= x.size) errors++;
        const uint32_t fmt = kMOpInfo[mi.op].fmt;
        if ((fmt == kFSop2 || fmt == kFSop1 || fmt == kFSopc) && x.cls == kVgpr) errors++;
        if (fmt == kFVop2 && k == 1 && !mi.mods && mi.op != m_v_cndmask_b32 && x.cls != kVgpr) errors++;
      }
    }
  }
  return errors;
}
} // namespace simv5
