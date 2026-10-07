// WorkloadRealisticV5Isel.h - Realistic V5 instruction selector (private to
// WorkloadRealisticV5Isel.cpp: operations, WorkloadRealisticV5IselCf.cpp:
// block layout, terminators and divergent control flow).
#pragma once
#include "workloads/WorkloadRealisticV5Alloc.h"
#include "workloads/WorkloadRealisticV5Mach.h"

namespace simv5 {
namespace isel {
constexpr uint32_t kModNeg = 1, kModAbs = 8; // IR source modifiers (<< operand slot)

// GFX9 inline constants: integers -16..64 and a few floats.
inline uint32_t InlineCode(uint32_t bits) {
  const int32_t i = (int32_t)bits;
  if (i >= 0 && i <= 64) return 128 + (uint32_t)i;
  if (i >= -16 && i < 0) return 192 + (uint32_t)-i;
  switch (bits) {
  case 0x3F000000u: return 240; case 0xBF000000u: return 241; case 0x3F800000u: return 242;
  case 0xBF800000u: return 243; case 0x40000000u: return 244; case 0xC0000000u: return 245;
  case 0x40800000u: return 246; case 0xC0800000u: return 247; case 0x3E22F983u: return 248;
  default: return kNone;
  }
}

class Isel {
public:
  Isel(Fn &f, Mach &m) : f_(f), m_(m), code_(m.code) {}
  void Run();

private:
  struct Cls {
    uint8_t cls, size;
  };
  // --- temporaries / instructions ---
  uint32_t NewTemp(uint8_t cls, uint8_t size) {
    MTemp t{};
    t.def = kNone;
    t.hint = t.fixed = kNone;
    t.phys = kPhysSpill;
    t.cls = cls;
    t.size = size;
    m_.temps.push_back(t);
    return (uint32_t)m_.temps.size() - 1;
  }
  uint32_t Lit(uint32_t bits) {
    const uint32_t c = InlineCode(bits);
    if (c != kNone) return kOInline | c;
    m_.scratch.push_back(bits); // literal table
    return kOLit | (uint32_t)(m_.scratch.size() - 1);
  }
  uint32_t Push(uint32_t op, uint32_t def, uint32_t a = kONone, uint32_t b = kONone, uint32_t c = kONone,
                uint32_t d = kONone) {
    MInst mi;
    std::memset(&mi, 0xFF, sizeof(mi));
    mi.op = (uint16_t)op;
    mi.mods = mi.flags = 0;
    mi.imm = 0;
    mi.defs[0] = def == kONone ? kONone : OTemp(def);
    mi.defs[1] = kONone;
    mi.ndefs = def == kONone ? 0 : 1;
    mi.ops[0] = a;
    mi.ops[1] = b;
    mi.ops[2] = c;
    mi.ops[3] = d;
    // Operand slots are positional (v_cndmask: mask in slot 3, exp: holes):
    // nops covers the last present slot, loops skip kONone.
    mi.nops = (uint8_t)(d != kONone ? 4 : c != kONone ? 3 : b != kONone ? 2 : a != kONone ? 1 : 0);
    mi.literal = 0;
    mi.node = node_;
    mi.block = cur_;
    mi.aux = kNone;
    mi.pad = 0;
    if (def != kONone) m_.temps[def].def = (uint32_t)code_.size();
    for (uint32_t k = 0; k < mi.nops; ++k)
      if (IsTempOp(mi.ops[k])) m_.temps[TempOf(mi.ops[k])].uses++;
    code_.push_back(mi);
    f_.st.machInsts++;
    return (uint32_t)code_.size() - 1;
  }
  const MTemp &T(uint32_t o) const { return m_.temps[TempOf(o)]; }
  bool IsV(uint32_t o) const { return IsTempOp(o) && T(o).cls == kVgpr; }
  bool IsS(uint32_t o) const { return IsTempOp(o) && T(o).cls == kSgpr; }
  bool IsLit(uint32_t o) const { return o != kONone && (o & kOKind) == kOLit; }
  uint32_t LitVal(uint32_t o) const { return m_.scratch[o & ~kOKind]; }

  // --- operands of IR values ---
  // May emit code (descriptor rematerialization): never pass two Val/V/S/Mask
  // calls as arguments of one call (unspecified evaluation order; MSVC
  // evaluates right to left -> compiler-dependent code and checksum).
  uint32_t Val(uint32_t v) {
    const Node &n = f_.nodes[v];
    if (IsConst(n)) return Lit((uint32_t)n.val);
    if (OpOf(n) == kDescLoad && IsInst(n)) return Desc(v);
    return n.reg; // selected before its uses (schedule order, dominance)
  }
  uint32_t ToV(uint32_t o) { // as_vgpr
    if (IsV(o)) return o;
    const uint32_t t = NewTemp(kVgpr, 1);
    Push(m_v_mov_b32, t, o);
    return OTemp(t);
  }
  uint32_t ToS(uint32_t o) { // as_uniform
    if (!IsV(o)) return o;
    const uint32_t t = NewTemp(kSgpr, 1);
    Push(m_v_readfirstlane_b32, t, o);
    return OTemp(t);
  }
  uint32_t V(uint32_t v) { return ToV(Val(v)); }
  uint32_t S(uint32_t v) { return ToS(Val(v)); }
  Cls ClassOf(uint32_t i) const;
  uint8_t Mods(const Node &n, uint32_t k) const {
    const uint32_t imm = (OpOf(n) == kExtract || HasFlag(OpOf(n), kMemRead | kSide)) ? 0 : n.imm;
    return (uint8_t)(((imm >> k) & kModNeg ? 1u << k : 0u) | ((imm >> k) & kModAbs ? 8u << k : 0u));
  }

  // --- legalized ALU emission ---
  uint32_t Salu(uint32_t op, uint8_t size, uint32_t a, uint32_t b = kONone) {
    a = ToS(a);
    b = b == kONone ? b : ToS(b);
    if (IsLit(a) && IsLit(b) && LitVal(a) != LitVal(b)) { // one literal per SALU instruction
      const uint32_t t = NewTemp(kSgpr, 1);
      Push(m_s_mov_b32, t, b);
      b = OTemp(t);
    }
    const uint32_t d = NewTemp(kSgpr, size);
    Push(op, d, a, b);
    f_.st.uniform++;
    return OTemp(d);
  }
  void Scmp(uint32_t op, uint32_t a, uint32_t b) {
    a = ToS(a);
    b = ToS(b);
    if (IsLit(a) && IsLit(b) && LitVal(a) != LitVal(b)) b = OTemp(MovS(b));
    Push(op, kONone, a, b);
  }
  uint32_t MovS(uint32_t o) {
    const uint32_t t = NewTemp(kSgpr, 1);
    Push(m_s_mov_b32, t, o);
    return t;
  }
  // VALU: VOP2 rules (src1 VGPR, one constant-bus read) unless the instruction
  // needs VOP3 (modifiers, three sources, VOPC / v_cndmask whose mask register
  // is known only after allocation): no literal, one SGPR read.
  uint32_t Valu(uint32_t op, uint32_t a, uint32_t b = kONone, uint32_t c = kONone, uint8_t mods = 0,
                uint8_t dcls = kVgpr, uint8_t dsize = 1, uint32_t maskSrc = kONone) {
    const uint32_t fmt = kMOpInfo[op].fmt;
    const bool vop3 = fmt == kFVop3 || fmt == kFVopc || op == m_v_cndmask_b32 || mods != 0;
    uint32_t s[3] = {a, b, c};
    if (fmt == kFVop2 && !vop3 && b != kONone && !IsV(b)) {
      if (MHas(op, kMComm) && IsV(a)) std::swap(s[0], s[1]);
      else if (op == m_v_sub_f32 && IsV(a)) { op = m_v_subrev_f32; std::swap(s[0], s[1]); }
      else if (op == m_v_sub_u32 && IsV(a)) { op = m_v_subrev_u32; std::swap(s[0], s[1]); }
      else s[1] = ToV(s[1]);
    }
    const bool maskBus = maskSrc != kONone && (maskSrc & kOKind) != kOInline;
    uint32_t bus = maskBus ? 1 : 0, sgpr = maskBus ? maskSrc : kONone, lit = kNone;
    for (uint32_t k = 0; k < 3; ++k) {
      uint32_t &o = s[k];
      if (o == kONone || IsV(o) || (o & kOKind) == kOInline) continue;
      if (IsLit(o) && vop3) { o = ToV(o); continue; }
      const bool same = IsLit(o) ? (lit != kNone && LitVal(o) == lit) : o == sgpr;
      if (same) continue;
      if (bus >= 1) { o = ToV(o); continue; } // GFX9: one constant-bus read
      bus++;
      if (IsLit(o)) lit = LitVal(o);
      else sgpr = o;
    }
    const uint32_t d = NewTemp(dcls, dsize);
    const uint32_t mi = Push(op, d, s[0], s[1], s[2], maskSrc);
    code_[mi].mods = mods;
    return OTemp(d);
  }
  uint32_t Vcmp(uint32_t op, uint32_t a, uint32_t b, uint8_t mods = 0) {
    return Valu(op, a, b, kONone, mods, kSgpr, 2);
  }
  // Booleans: SCC from a uniform bool / lane mask; lane mask from any bool.
  void Scc(uint32_t o) {
    if (!IsTempOp(o)) {
      Push(m_s_cmp_lg_u32, kONone, MovSOp(o), kOInline | 128);
      return;
    }
    o = ToS(o);
    Push(T(o).size == 2 ? m_s_cmp_lg_u64 : m_s_cmp_lg_u32, kONone, o, kOInline | 128);
  }
  uint32_t MovSOp(uint32_t o) { return OTemp(MovS(o)); }
  uint32_t Mask(uint32_t v) {
    const Node &n = f_.nodes[v];
    if (IsConst(n)) return kOInline | ((n.val & 1) ? 193u : 128u);
    const uint32_t o = Val(v);
    if (IsTempOp(o) && T(o).cls == kSgpr && T(o).size == 2) return o;
    Scc(o);
    const uint32_t m = NewTemp(kSgpr, 2);
    Push(m_s_cselect_b64, m, kOFixed | kRegExec, kOInline | 128);
    return OTemp(m);
  }
  uint32_t BoolFromScc() {
    const uint32_t d = NewTemp(kSgpr, 1);
    Push(m_s_cselect_b32, d, kOInline | 129, kOInline | 128);
    return OTemp(d);
  }
  uint32_t BoolFromMask(uint32_t m) {
    Push(m_s_cmp_lg_u64, kONone, m, kOInline | 128);
    return BoolFromScc();
  }
  uint32_t Sampler(uint32_t handle);
  uint32_t Desc(uint32_t handle);
  uint32_t SelectIdiv(uint32_t op, uint32_t a, uint32_t b);
  uint32_t SelectCompare(uint32_t i, const Node &n);
  void SelectNode(uint32_t i);
  void Terminator(uint32_t b);
  void AnalyzeCf();
  uint32_t ExecOp(uint32_t op, uint32_t a, uint32_t b);
  void FlushExports(bool last);
  uint32_t Target(uint32_t from, uint32_t to) const;
  void Layout();

  Fn &f_;
  Mach &m_;
  InstrList &code_;
  uint32_t cur_ = 0, node_ = kNone;
  uint32_t desc_ = kONone, prim_ = kONone, grp_ = kONone, bary_[2] = {kONone, kONone};
  uint32_t tid_[3] = {kONone, kONone, kONone};
  bool compute_ = false;
  uint32_t exports_[4] = {kONone, kONone, kONone, kONone};
  DenseMap32 sampMap_, descMap_; // per machine block: handle node -> descriptor temporary
};
} // namespace isel
} // namespace simv5
