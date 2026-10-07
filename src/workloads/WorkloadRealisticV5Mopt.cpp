// WorkloadRealisticV5Mopt.cpp - Realistic V5 machine-code optimizer (ACO's
// aco_optimizer in spirit): a per-temporary label table (ssa_info: constant,
// negated / absolute source, bool-to-int, single-use shift / add / multiply)
// filled in one forward sweep that also rewrites operands — inline constants
// into legal slots, fneg / fabs into VOP3 source modifiers, v_cmp_ne(b2i(m),
// 0) back to m — and combines v_add(v_lshl(x, s), y) -> v_lshl_add_u32,
// v_add(v_add(a, b), c) -> v_add3_u32, v_add_f32(v_mul_f32(a, b), c) ->
// v_mad_f32 under the VOP3 operand rules. A backward sweep removes
// instructions whose results lost all uses, then the code is compacted.
#include "workloads/WorkloadRealisticV5Mach.h"
#include "workloads/WorkloadRealisticV5Alloc.h"
#include "workloads/WorkloadRealisticV5Replica.h"
#ifdef SIMV5_DEAD_TRACE
#include <cstdio>
#endif

namespace simv5 {
namespace {
enum Label : uint8_t { kLNone, kLConst, kLNeg, kLAbs, kLB2I, kLShl, kLAdd, kLMul, kLCopy };
struct Info {
  uint8_t label;
  uint8_t inl;     // kLConst: inline source code available
  uint16_t code;   // kLConst: inline code
  uint32_t val;    // constant bits, source temporary operand, or instruction index
};
static_assert(sizeof(Info) == 8, "ssa_info is 8 bytes");

class Optimizer {
public:
  Optimizer(Fn &f, Mach &m) : f_(f), m_(m) {}
  void Run();

private:
  Info &I(uint32_t o) { return info_[TempOf(o)]; }
  void Use(uint32_t o, int d) {
    if (IsTempOp(o)) m_.temps[TempOf(o)].uses += d;
  }
  void SetOp(MInst &mi, uint32_t k, uint32_t o) {
    Use(mi.ops[k], -1);
    mi.ops[k] = o;
    Use(o, +1);
  }
  bool IsV(uint32_t o) const { return IsTempOp(o) && m_.temps[TempOf(o)].cls == kVgpr; }
  bool IsS(uint32_t o) const { return IsTempOp(o) && m_.temps[TempOf(o)].cls == kSgpr; }
  // VOP3 rules (GFX9): no literal, one constant-bus read (SGPR) at most.
  bool Vop3Ok(const uint32_t *ops, uint32_t n) const {
    uint32_t sgpr = kONone;
    for (uint32_t k = 0; k < n; ++k) {
      const uint32_t o = ops[k];
      if (o == kONone) continue;
      if ((o & kOKind) == kOLit) return false;
      if (IsS(o) || (o & kOKind) == kOFixed) {
        if (sgpr != kONone && sgpr != o) return false;
        sgpr = o;
      }
    }
    return true;
  }
  bool InlineSlot(const MInst &mi, uint32_t k) const;
  void Rewrite(MInst &mi, uint32_t op, uint32_t a, uint32_t b, uint32_t c, uint8_t mods);
  template <uint32_t R> void Forward(uint32_t i);
  template <uint32_t R> struct PickForward {
    static constexpr void (Optimizer::*value)(uint32_t) = &Optimizer::Forward<R>;
  };
  static constexpr auto kForward = ReplicaTable<void (Optimizer::*)(uint32_t), PickForward>(
      std::make_integer_sequence<uint32_t, kReplicas>{});
  void Label(uint32_t i);
  void ValueNumbering();
  uint32_t Hash(const MInst &mi) const;
  bool Same(const MInst &a, const MInst &b) const;
  uint8_t *dead_ = nullptr;
  Fn &f_;
  Mach &m_;
  std::vector<uint64_t> &store_ = m_.liveOut; // borrowed storage for the label table
  Info *info_ = nullptr;
};

// Operand slots that may take an inline constant without changing encoding
// rules: SALU sources, VOP1/VOPC/VOP3 sources, VOP2 src0 (src1 must be a VGPR).
bool Optimizer::InlineSlot(const MInst &mi, uint32_t k) const {
  const uint32_t fmt = kMOpInfo[mi.op].fmt;
  switch (fmt) {
  case kFSop2: case kFSop1: case kFSopc: return true;
  case kFVop1: return k == 0 && mi.op != m_v_readfirstlane_b32;
  case kFVop3: case kFVopc: return k < 3;
  case kFVop2: return k == 0 || (mi.op == m_v_cndmask_b32 && k == 1); // cndmask: VOP3 when src1 is not a VGPR
  default: return false; // memory, exports, interpolation, pseudo
  }
}

void Optimizer::Rewrite(MInst &mi, uint32_t op, uint32_t a, uint32_t b, uint32_t c, uint8_t mods) {
  const uint32_t ops[3] = {a, b, c};
  for (uint32_t k = 0; k < 3; ++k) Use(ops[k], +1);
  for (uint32_t k = 0; k < 4; ++k) Use(mi.ops[k], -1);
  mi.op = (uint16_t)op;
  mi.ops[0] = a;
  mi.ops[1] = b;
  mi.ops[2] = c;
  mi.ops[3] = kONone;
  mi.nops = (uint8_t)(c != kONone ? 3 : b != kONone ? 2 : a != kONone ? 1 : 0);
  mi.mods = mods;
  f_.st.moptCombines++;
}

template <uint32_t R> NOINLINE void Optimizer::Forward(uint32_t i) {
  SIMV5_REPLICA_TAG(R);
  MInst &mi = m_.code[i];
  const uint32_t fmt = kMOpInfo[mi.op].fmt;
  if (fmt == kFPseudo && mi.op != m_p_create_vector) return;
  // Operand rewrites from the labels of their definitions.
  for (uint32_t k = 0; k < mi.nops; ++k) {
    const uint32_t o = mi.ops[k];
    if (!IsTempOp(o) || SubOf(o)) continue;
    const Info in = I(o);
    if (in.label == kLCopy) {
      SetOp(mi, k, in.val);
      f_.st.moptCopies++;
    } else if (in.label == kLConst && in.inl && InlineSlot(mi, k)) {
      SetOp(mi, k, kOInline | in.code);
      f_.st.moptConsts++;
    } else if ((in.label == kLNeg || in.label == kLAbs) && MHas(mi.op, kMFloat) && k < 3 &&
               (fmt == kFVop2 || fmt == kFVop3 || fmt == kFVopc) && mi.op != m_v_cvt_u32_f32 &&
               mi.op != m_v_cvt_i32_f32) {
      uint32_t ops[3] = {mi.ops[0], mi.ops[1], mi.ops[2]};
      ops[k] = in.val;
      if (!Vop3Ok(ops, 3)) continue;
      SetOp(mi, k, in.val);
      // Hardware applies abs, then neg. Operand -x: under abs nothing changes,
      // otherwise the negation toggles. Operand |x|: set abs, keep the neg.
      if (in.label == kLAbs) mi.mods |= (uint8_t)(8u << k);
      else if (!(mi.mods & (8u << k))) mi.mods ^= (uint8_t)(1u << k);
      f_.st.moptMods++;
    }
  }
  // Instruction combines.
  auto single = [&](uint32_t o, uint8_t label) -> int32_t {
    if (!IsTempOp(o) || SubOf(o) || I(o).label != label || m_.temps[TempOf(o)].uses != 1) return -1;
    return (int32_t)I(o).val;
  };
  if ((mi.op == m_v_cmp_ne_u32 || mi.op == m_v_cmp_ne_i32) && mi.mods == 0) {
    for (uint32_t k = 0; k < 2; ++k)
      if (IsTempOp(mi.ops[k]) && !SubOf(mi.ops[k]) && I(mi.ops[k]).label == kLB2I && mi.ops[1 - k] == (kOInline | 128) &&
          IsTempOp(mi.defs[0])) {
        info_[TempOf(mi.defs[0])] = {kLCopy, 0, 0, I(mi.ops[k]).val}; // the original lane mask
        f_.st.moptCombines++;
        return;
      }
  }
  if (mi.op == m_v_add_u32 && mi.mods == 0) {
    for (uint32_t k = 0; k < 2; ++k) {
      const int32_t s = single(mi.ops[k], kLShl);
      if (s >= 0) {
        const MInst &sh = m_.code[(uint32_t)s];
        const uint32_t ops[3] = {sh.ops[1], sh.ops[0], mi.ops[1 - k]};
        if (Vop3Ok(ops, 3)) {
          const uint32_t keep = mi.ops[k];
          Rewrite(mi, m_v_lshl_add_u32, ops[0], ops[1], ops[2], 0);
          (void)keep;
          return;
        }
      }
      const int32_t a = single(mi.ops[k], kLAdd);
      if (a >= 0) {
        const MInst &ad = m_.code[(uint32_t)a];
        const uint32_t ops[3] = {ad.ops[0], ad.ops[1], mi.ops[1 - k]};
        if (Vop3Ok(ops, 3)) {
          Rewrite(mi, m_v_add3_u32, ops[0], ops[1], ops[2], 0);
          return;
        }
      }
    }
  }
  if (mi.op == m_v_add_f32 && mi.mods == 0) {
    for (uint32_t k = 0; k < 2; ++k) {
      const int32_t mu = single(mi.ops[k], kLMul);
      if (mu < 0) continue;
      const MInst &ml = m_.code[(uint32_t)mu];
      const uint32_t ops[3] = {ml.ops[0], ml.ops[1], mi.ops[1 - k]};
      if (Vop3Ok(ops, 3)) {
        Rewrite(mi, m_v_mad_f32, ops[0], ops[1], ops[2], 0);
        return;
      }
    }
  }
}

void Optimizer::Label(uint32_t i) {
  const MInst &mi = m_.code[i];
  if (mi.ndefs == 0 || !IsTempOp(mi.defs[0])) return;
  Info &d = info_[TempOf(mi.defs[0])];
  if (d.label == kLCopy) return;
  const uint32_t a = mi.ops[0], b = mi.ops[1];
  auto lit = [&](uint32_t o, uint32_t v) {
    return o != kONone && (((o & kOKind) == kOLit && m_.scratch[o & ~kOKind] == v));
  };
  switch (mi.op) {
  case m_s_mov_b32: case m_v_mov_b32:
    if ((a & kOKind) == kOInline) d = {kLConst, 1, (uint16_t)(a & 0x1FF), 0};
    else if ((a & kOKind) == kOLit) d = {kLConst, 0, 0, m_.scratch[a & ~kOKind]};
    break;
  case m_v_xor_b32:
    if (lit(a, 0x80000000u) && IsV(b) && !SubOf(b)) d = {kLNeg, 0, 0, b};
    break;
  case m_v_and_b32:
    if (lit(a, 0x7FFFFFFFu) && IsV(b) && !SubOf(b)) d = {kLAbs, 0, 0, b};
    break;
  case m_v_cndmask_b32:
    if (a == (kOInline | 128) && b == (kOInline | 129) && IsTempOp(mi.ops[3])) d = {kLB2I, 0, 0, mi.ops[3]};
    break;
  case m_v_lshlrev_b32:
    if (mi.mods == 0) d = {kLShl, 0, 0, i};
    break;
  case m_v_add_u32:
    if (mi.mods == 0) d = {kLAdd, 0, 0, i};
    break;
  case m_v_mul_f32:
    if (mi.mods == 0) d = {kLMul, 0, 0, i};
    break;
  default: break;
  }
}

// Value numbering (ACO opt_value_numbering): exec is constant inside a block,
// so a block-local hash map from opcode / operands / modifiers to the first
// occurrence finds duplicates (repeated descriptor and constant-buffer loads,
// conversions, address math); later uses are renamed to the first result.
uint32_t Optimizer::Hash(const MInst &mi) const {
  uint32_t h = mi.op * 0x9E3779B1u ^ mi.mods << 7 ^ mi.flags << 13 ^ mi.imm << 16;
  for (uint32_t k = 0; k < mi.nops; ++k) {
    const uint32_t o = mi.ops[k];
    const uint32_t v = (o & kOKind) == kOLit ? m_.scratch[o & ~kOKind] ^ 0x5A5A5A5Au : o;
    h = (h ^ v) * 0x01000193u;
  }
  return (h ^ (h >> 16)) & 0x7FFFFFFFu; // keys 0xFFFFFFFE / 0xFFFFFFFF are reserved
}
bool Optimizer::Same(const MInst &a, const MInst &b) const {
  if (a.op != b.op || a.mods != b.mods || a.flags != b.flags || a.imm != b.imm || a.nops != b.nops) return false;
  for (uint32_t k = 0; k < a.nops; ++k) {
    const uint32_t x = a.ops[k], y = b.ops[k];
    if ((x & kOKind) == kOLit && (y & kOKind) == kOLit) {
      if (m_.scratch[x & ~kOKind] != m_.scratch[y & ~kOKind]) return false;
    } else if (x != y) {
      return false;
    }
  }
  const MTemp &ta = m_.temps[TempOf(a.defs[0])], &tb = m_.temps[TempOf(b.defs[0])];
  return ta.cls == tb.cls && ta.size == tb.size;
}
void Optimizer::ValueNumbering() {
  DenseMap32 table, renames;
  auto rename = [&](MInst &mi) {
    for (uint32_t k = 0; k < mi.nops; ++k) {
      if (!IsTempOp(mi.ops[k])) continue;
      if (const uint32_t *r = renames.Find(TempOf(mi.ops[k]))) SetOp(mi, k, OTemp(*r, SubOf(mi.ops[k])));
    }
  };
  for (const MBlock &mb : m_.blocks) {
    table.Clear();
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      MInst &mi = m_.code[i];
      rename(mi);
      const uint32_t fmt = kMOpInfo[mi.op].fmt;
      const bool pure = fmt == kFSop1 || fmt == kFSop2 || fmt == kFSmem || fmt == kFVop1 || fmt == kFVop2 ||
                        fmt == kFVop3 || fmt == kFVopc || fmt == kFVintrp;
      if (!pure || mi.ndefs != 1 || !IsTempOp(mi.defs[0]) || MHas(mi.op, kMRScc)) continue;
      const uint32_t h = Hash(mi);
      uint32_t *slot = table.Find(h);
      if (slot && Same(m_.code[*slot], mi)) {
        renames[TempOf(mi.defs[0])] = TempOf(m_.code[*slot].defs[0]);
        dead_[i] = 1;
        for (uint32_t k = 0; k < mi.nops; ++k) Use(mi.ops[k], -1);
        f_.st.vnHits++;
        continue;
      }
      table[h] = i;
    }
  }
  for (MInst &mi : m_.code) // back-edge phi operands defined after their phi
    if (mi.op == m_p_phi) rename(mi);
}

void Optimizer::Run() {
  const uint32_t nt = (uint32_t)m_.temps.size(), n = (uint32_t)m_.code.size();
  store_.assign((nt + 1) * sizeof(Info) / 8 + 1, 0);
  info_ = reinterpret_cast<Info *>(store_.data());
  std::vector<uint8_t> &dead = m_.bytes;
  dead.assign(n, 0);
  dead_ = dead.data();
  ValueNumbering();
  for (uint32_t i = 0; i < n; ++i) {
    if (dead[i]) continue;
    (this->*kForward[ReplicaOf(m_.code[i].block)])(i); // the block's code replica
    Label(i);
  }
  // Backward: drop instructions whose results are unused (no side effects).
  for (uint32_t i = n; i-- > 0;) {
    const MInst &mi = m_.code[i];
    if (dead[i] || mi.ndefs == 0 || MHas(mi.op, kMStore | kMBranch) || mi.op == m_p_startpgm) continue;
    bool unused = true;
    for (uint32_t d = 0; d < mi.ndefs && unused; ++d)
      unused = IsTempOp(mi.defs[d]) && m_.temps[TempOf(mi.defs[d])].uses == 0;
    if (!unused) continue;
    dead[i] = 1;
#ifdef SIMV5_DEAD_TRACE
    if (f_.diag && mi.node != kNone) {
      const Node &n = f_.nodes[mi.node];
      const uint32_t u = n.firstUse == kNone ? kNone : UseUser(n.firstUse);
      std::fprintf(stderr, "mdead %u node %u uses %u user %u userop %08x userblock %u myblock %u reg %08x%c", mi.op, OpOf(n),
                   n.numUses, u, u == kNone ? 0 : f_.nodes[u].op, u == kNone ? 0 : f_.nodes[u].block, n.block, n.reg, 10);
    }
#endif
    for (uint32_t k = 0; k < mi.nops; ++k) Use(mi.ops[k], -1);
    f_.st.moptDead++;
  }
  // Compact (block ranges follow) and renumber definitions.
  m_.tmp.clear();
  for (MBlock &mb : m_.blocks) {
    const uint32_t start = (uint32_t)m_.tmp.size();
    uint32_t term = kNone;
    for (uint32_t i = mb.start; i < mb.end; ++i) {
      if (i == mb.term) term = (uint32_t)m_.tmp.size();
      if (!dead[i]) m_.tmp.take(m_.code, i); // dead ones are freed with the old list
    }
    mb.start = start;
    mb.end = (uint32_t)m_.tmp.size();
    mb.term = term == kNone ? mb.end : term;
  }
  m_.code.swap(m_.tmp);
  for (uint32_t i = 0; i < m_.code.size(); ++i) {
    const MInst &mi = m_.code[i];
    for (uint32_t d = 0; d < mi.ndefs; ++d)
      if (IsTempOp(mi.defs[d])) m_.temps[TempOf(mi.defs[d])].def = i;
    // v_mad_f32 whose addend dies here prefers the addend's register: the
    // copy lowering then encodes the 4-byte v_mac_f32 (tied destination).
    if (mi.op == m_v_mad_f32 && !mi.mods && IsV(mi.ops[2]) && !SubOf(mi.ops[2]) &&
        m_.temps[TempOf(mi.ops[2])].uses == 1 && IsTempOp(mi.defs[0]))
      m_.temps[TempOf(mi.defs[0])].hint = 0x80000000u | TempOf(mi.ops[2]);
  }
}
} // namespace

void OptimizeMachine(Fn &f, Mach &m) {
  Optimizer opt(f, m);
  opt.Run();
}
} // namespace simv5
