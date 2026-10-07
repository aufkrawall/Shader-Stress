// WorkloadRealisticV5Isel.cpp - Realistic V5 instruction selection, as in
// ACO's instruction_selection: the scheduled IR becomes GFX9-like machine
// code on virtual temporaries. Divergence decides the register class: uniform
// integer values live in SGPRs (SALU, results of VALU-only operations are
// made uniform with v_readfirstlane), floats and divergent values in VGPRs;
// uniform booleans are 0/1 SGPRs, divergent booleans 64-bit lane masks.
// Operand legalization follows the hardware rules (VOP2 src1 must be a VGPR,
// one constant-bus read per VALU instruction, no literal in VOP3, one literal
// per SALU instruction). Phis become p_phi with operands per machine
// predecessor; critical edges into phi blocks get their own machine block.
#include "workloads/WorkloadRealisticV5Mach.h"

namespace simv5 {
namespace {
constexpr uint32_t kModNeg = 1, kModAbs = 8; // IR source modifiers (<< operand slot)

// GFX9 inline constants: integers -16..64 and a few floats.
uint32_t InlineCode(uint32_t bits) {
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
    mi.nops = (uint8_t)((a != kONone) + (b != kONone) + (c != kONone) + (d != kONone));
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
  void FlushExports(bool last);
  uint32_t Target(uint32_t from, uint32_t to) const;
  void Layout();

  Fn &f_;
  Mach &m_;
  std::vector<MInst> &code_;
  uint32_t cur_ = 0, node_ = kNone;
  uint32_t desc_ = kONone, prim_ = kONone, grp_ = kONone, bary_[2] = {kONone, kONone};
  uint32_t tid_[3] = {kONone, kONone, kONone};
  bool compute_ = false;
  uint32_t exports_[4] = {kONone, kONone, kONone, kONone};
  uint32_t samp_[8][2], desc2_[16][2];
  uint32_t nsamp_ = 0, ndesc_ = 0;
};

Isel::Cls Isel::ClassOf(uint32_t i) const {
  const Node &n = f_.nodes[i];
  const bool u = !(n.op & kDivergentFlag);
  const uint32_t op = IsPhi(n) ? kNotAnOp : OpOf(n);
  if (n.type == kI1) return {kSgpr, (uint8_t)(u ? 1 : 2)};
  if (n.type == kHandle) {
    for (uint32_t k = n.firstUse; k != kNone; k = f_.nodes[UseUser(k)].useNext[k & 3]) {
      const uint32_t uo = OpOf(f_.nodes[UseUser(k)]);
      if (uo == kImageSample || uo == kImageLoad) return {kSgpr, 8};
    }
    return {kSgpr, 4};
  }
  if (IsResRet(n.type)) return {(uint8_t)(op == kLoadUboX4 && u ? kSgpr : kVgpr), 4};
  if (IsFloatTy(n.type)) return {(uint8_t)(u && op == kLoadUbo ? kSgpr : kVgpr), 1};
  return {(uint8_t)(u ? kSgpr : kVgpr), 1};
}

// Sampler descriptor of a texture (cached per machine block).
uint32_t Isel::Sampler(uint32_t handle) {
  for (uint32_t k = 0; k < nsamp_; ++k)
    if (samp_[k][0] == handle) return samp_[k][1];
  const uint32_t t = NewTemp(kSgpr, 4);
  const uint32_t mi = Push(m_s_load_dwordx4, t, desc_);
  code_[mi].imm = (uint16_t)(0x200 + (handle & 31) * 16);
  code_[mi].flags = kMfOffset;
  if (nsamp_ < 8) {
    samp_[nsamp_][0] = handle;
    samp_[nsamp_++][1] = OTemp(t);
  }
  return OTemp(t);
}

// Resource descriptor (RADV: loaded from the descriptor set where it is used,
// CSE'd within a block) instead of keeping 4-8 SGPRs live across the shader.
uint32_t Isel::Desc(uint32_t handle) {
  for (uint32_t k = 0; k < ndesc_; ++k)
    if (desc2_[k][0] == handle) return desc2_[k][1];
  const Cls c = ClassOf(handle);
  const Node &n = f_.nodes[handle], &rg = f_.nodes[n.a];
  const uint32_t saved = node_;
  node_ = handle;
  const uint32_t off = IsConst(rg) ? kONone : Salu(m_s_lshl_b32, 1, Val(n.a), kOInline | 133);
  const uint32_t d = NewTemp(kSgpr, c.size);
  const uint32_t mi = Push(c.size == 8 ? m_s_load_dwordx8 : m_s_load_dwordx4, d, desc_, off);
  code_[mi].imm = (uint16_t)((IsConst(rg) ? (uint32_t)rg.val & 63 : 0) * 32);
  code_[mi].flags = kMfOffset;
  node_ = saved;
  if (ndesc_ < 16) {
    desc2_[ndesc_][0] = handle;
    desc2_[ndesc_++][1] = OTemp(d);
  }
  return OTemp(d);
}

// Integer division by a variable (nir_lower_idiv / ACO): reciprocal estimate,
// one Newton-Raphson step on the integer reciprocal, quotient and correction.
uint32_t Isel::SelectIdiv(uint32_t op, uint32_t a, uint32_t b) {
  const uint32_t vb = ToV(b);
  const uint32_t fb = Valu(m_v_cvt_f32_u32, vb);
  const uint32_t r = Valu(m_v_rcp_iflag_f32, fb);
  const uint32_t s = Valu(m_v_mul_f32, Lit(0x4F7FFFFEu), r);
  const uint32_t inv = Valu(m_v_cvt_u32_f32, s);
  const uint32_t nb = Valu(m_v_sub_u32, kOInline | 128, vb);
  const uint32_t e = Valu(m_v_mul_lo_u32, nb, inv);
  const uint32_t h = Valu(m_v_mul_hi_u32, inv, e);
  const uint32_t inv2 = Valu(m_v_add_u32, inv, h);
  const uint32_t q = Valu(m_v_mul_hi_u32, a, inv2);
  const uint32_t qb = Valu(m_v_mul_lo_u32, q, vb);
  const uint32_t rem = Valu(m_v_sub_u32, a, qb);
  const uint32_t ge = Vcmp(m_v_cmp_ge_u32, rem, vb);
  if (op == kURem || op == kSRem) {
    const uint32_t r1 = Valu(m_v_sub_u32, rem, vb);
    return Valu(m_v_cndmask_b32, rem, r1, kONone, 0, kVgpr, 1, ge);
  }
  const uint32_t q1 = Valu(m_v_add_u32, kOInline | 129, q);
  return Valu(m_v_cndmask_b32, q, q1, kONone, 0, kVgpr, 1, ge);
}

uint32_t Isel::SelectCompare(uint32_t i, const Node &n) {
  static constexpr uint16_t kV[] = {
      m_v_cmp_eq_u32, m_v_cmp_ne_u32, m_v_cmp_gt_u32, m_v_cmp_ge_u32, m_v_cmp_lt_u32, m_v_cmp_le_u32,
      m_v_cmp_gt_i32, m_v_cmp_ge_i32, m_v_cmp_lt_i32, m_v_cmp_le_i32, m_v_cmp_eq_f32, m_v_cmp_gt_f32,
      m_v_cmp_ge_f32, m_v_cmp_lt_f32, m_v_cmp_le_f32, m_v_cmp_lg_f32, m_v_cmp_o_f32, m_v_cmp_u_f32,
      m_v_cmp_nlg_f32, m_v_cmp_neq_f32};
  static constexpr uint16_t kS[] = {m_s_cmp_eq_u32, m_s_cmp_lg_u32, m_s_cmp_gt_u32, m_s_cmp_ge_u32,
                                    m_s_cmp_lt_u32, m_s_cmp_le_u32, m_s_cmp_gt_i32, m_s_cmp_ge_i32,
                                    m_s_cmp_lt_i32, m_s_cmp_le_i32};
  const uint32_t k = OpOf(n) - kICmpEq;
  const bool fl = OpOf(n) >= kFCmpOeq;
  const bool u = !(n.op & kDivergentFlag);
  (void)i;
  if (!fl && u) {
    Scmp(kS[k], Val(n.a), Val(n.b));
    return BoolFromScc();
  }
  const uint32_t m = Vcmp(kV[k], Val(n.a), Val(n.b), Mods(n, 0) | Mods(n, 1));
  return u ? BoolFromMask(m) : m;
}

void Isel::SelectNode(uint32_t i) {
  Node &n = f_.nodes[i];
  node_ = i;
  const uint32_t op = OpOf(n);
  const bool u = !(n.op & kDivergentFlag);
  uint32_t r = kONone;
  auto unary = [&](uint32_t sop, uint32_t vop) { r = u && sop != kMOpCount ? Salu(sop, 1, Val(n.a)) : Valu(vop, Val(n.a)); };
  auto binary = [&](uint32_t sop, uint32_t vop) {
    r = u ? Salu(sop, 1, Val(n.a), Val(n.b)) : Valu(vop, Val(n.a), Val(n.b));
  };
  auto fbin = [&](uint32_t vop) { r = Valu(vop, Val(n.a), Val(n.b), kONone, Mods(n, 0) | Mods(n, 1)); };
  switch (op) {
  case kIAdd: binary(m_s_add_u32, m_v_add_u32); break;
  case kISub: binary(m_s_sub_u32, m_v_sub_u32); break;
  case kIMul: binary(m_s_mul_i32, m_v_mul_lo_u32); break;
  case kUDiv: case kSDiv: case kURem: case kSRem: r = SelectIdiv(op, Val(n.a), Val(n.b)); break;
  case kShl: case kLShr: case kAShr: {
    static constexpr uint16_t kSs[] = {m_s_lshl_b32, m_s_lshr_b32, m_s_ashr_i32};
    static constexpr uint16_t kVs[] = {m_v_lshlrev_b32, m_v_lshrrev_b32, m_v_ashrrev_i32};
    r = u ? Salu(kSs[op - kShl], 1, Val(n.a), Val(n.b)) : Valu(kVs[op - kShl], Val(n.b), V(n.a));
    break;
  }
  case kAnd: case kOr: case kXor: {
    const uint32_t k = op - kAnd;
    if (n.type == kI1 && !u) {
      static constexpr uint16_t kM[] = {m_s_and_b64, m_s_or_b64, m_s_xor_b64};
      const uint32_t ma = Mask(n.a), mb = Mask(n.b);
      r = Salu(kM[k], 2, ma, mb);
    } else {
      static constexpr uint16_t kSb[] = {m_s_and_b32, m_s_or_b32, m_s_xor_b32};
      static constexpr uint16_t kVb[] = {m_v_and_b32, m_v_or_b32, m_v_xor_b32};
      binary(kSb[k], kVb[k]);
    }
    break;
  }
  case kFAdd: fbin(m_v_add_f32); break;
  case kFSub: fbin(m_v_sub_f32); break;
  case kFMul: fbin(m_v_mul_f32); break;
  case kFMin: fbin(m_v_min_f32); break;
  case kFMax: fbin(m_v_max_f32); break;
  case kFDiv: {
    const uint32_t rc = Valu(m_v_rcp_f32, Val(n.b));
    r = Valu(m_v_mul_f32, Val(n.a), rc);
    break;
  }
  case kFMad: case kFma:
    r = Valu(op == kFMad ? m_v_mad_f32 : m_v_fma_f32, Val(n.a), Val(n.b), Val(n.c),
             Mods(n, 0) | Mods(n, 1) | Mods(n, 2));
    break;
  case kFNeg: r = Valu(m_v_xor_b32, Lit(0x80000000u), V(n.a)); break;
  case kFAbs: r = Valu(m_v_and_b32, Lit(0x7FFFFFFFu), V(n.a)); break;
  case kSaturate: r = Valu(m_v_add_f32, kOInline | 128, Val(n.a), kONone, (uint8_t)(0x40 | Mods(n, 0) << 1)); break;
  case kIsNaN: case kIsInf: {
    const uint32_t m = Vcmp(m_v_cmp_class_f32, Val(n.a), op == kIsNaN ? kOInline | 131 : Lit(0x204));
    r = u ? BoolFromMask(m) : m;
    break;
  }
  case kSin: case kCos: {
    const uint32_t t = Valu(m_v_mul_f32, kOInline | 248, Val(n.a));
    r = Valu(op == kSin ? m_v_sin_f32 : m_v_cos_f32, t);
    break;
  }
  case kExp: unary(kMOpCount, m_v_exp_f32); break;
  case kLog: unary(kMOpCount, m_v_log_f32); break;
  case kSqrt: unary(kMOpCount, m_v_sqrt_f32); break;
  case kRsqrt: unary(kMOpCount, m_v_rsq_f32); break;
  case kRcp: unary(kMOpCount, m_v_rcp_f32); break;
  case kFrc: unary(kMOpCount, m_v_fract_f32); break;
  case kRoundNe: unary(kMOpCount, m_v_rndne_f32); break;
  case kRoundNi: unary(kMOpCount, m_v_floor_f32); break;
  case kRoundPi: unary(kMOpCount, m_v_ceil_f32); break;
  case kRoundZ: unary(kMOpCount, m_v_trunc_f32); break;
  case kBfrev: unary(m_s_brev_b32, m_v_bfrev_b32); break;
  case kFirstbitLo: unary(m_s_ff1_i32_b32, m_v_ffbl_b32); break;
  case kFirstbitHi: unary(m_s_flbit_i32_b32, m_v_ffbh_u32); break;
  case kCountbits:
    r = u ? Salu(m_s_bcnt1_i32_b32, 1, Val(n.a)) : Valu(m_v_bcnt_u32_b32, Val(n.a), kOInline | 128);
    break;
  case kIMax: binary(m_s_max_i32, m_v_max_i32); break;
  case kIMin: binary(m_s_min_i32, m_v_min_i32); break;
  case kUMax: binary(m_s_max_u32, m_v_max_u32); break;
  case kUMin: binary(m_s_min_u32, m_v_min_u32); break;
  case kUMulHi: binary(m_s_mul_hi_u32, m_v_mul_hi_u32); break;
  case kIMulHi: binary(m_s_mul_hi_i32, m_v_mul_hi_i32); break;
  case kIMad: case kUMad:
    if (u) r = Salu(m_s_add_u32, 1, Salu(m_s_mul_i32, 1, Val(n.a), Val(n.b)), Val(n.c));
    else r = Valu(m_v_add_u32, Val(n.c), Valu(m_v_mul_lo_u32, Val(n.a), Val(n.b)));
    break;
  case kIbfe: case kUbfe: { // dx.op.bfe(width, offset, value)
    if (!u) {
      r = Valu(op == kUbfe ? m_v_bfe_u32 : m_v_bfe_i32, Val(n.c), Val(n.b), Val(n.a));
      break;
    }
    uint32_t packed;
    if (IsConst(f_.nodes[n.a]) && IsConst(f_.nodes[n.b]))
      packed = Lit(((uint32_t)f_.nodes[n.b].val & 31) | ((uint32_t)f_.nodes[n.a].val & 31) << 16);
    else
      packed = Salu(m_s_or_b32, 1, Salu(m_s_lshl_b32, 1, Val(n.a), kOInline | 144), Val(n.b));
    r = Salu(op == kUbfe ? m_s_bfe_u32 : m_s_bfe_i32, 1, Val(n.c), packed);
    break;
  }
  case kICmpEq: case kICmpNe: case kICmpUgt: case kICmpUge: case kICmpUlt: case kICmpUle:
  case kICmpSgt: case kICmpSge: case kICmpSlt: case kICmpSle: case kFCmpOeq: case kFCmpOgt:
  case kFCmpOge: case kFCmpOlt: case kFCmpOle: case kFCmpOne: case kFCmpOrd: case kFCmpUno:
  case kFCmpUeq: case kFCmpUne:
    r = SelectCompare(i, n);
    break;
  case kTrunc:
    if (n.type != kI1) r = Val(n.a);
    else if (u) r = Salu(m_s_and_b32, 1, Val(n.a), kOInline | 129);
    else r = Vcmp(m_v_cmp_ne_u32, Valu(m_v_and_b32, kOInline | 129, V(n.a)), kOInline | 128);
    break;
  case kZExt: case kSExt: {
    if (f_.nodes[n.a].type != kI1) { r = Val(n.a); break; }
    const uint32_t one = op == kZExt ? kOInline | 129 : kOInline | 193;
    if (u) {
      Scc(Val(n.a));
      const uint32_t d = NewTemp(kSgpr, 1);
      Push(m_s_cselect_b32, d, one, kOInline | 128);
      r = OTemp(d);
    } else {
      r = Valu(m_v_cndmask_b32, kOInline | 128, one, kONone, 0, kVgpr, 1, Mask(n.a));
    }
    break;
  }
  case kFPToSI: unary(kMOpCount, m_v_cvt_i32_f32); break;
  case kFPToUI: unary(kMOpCount, m_v_cvt_u32_f32); break;
  case kSIToFP: unary(kMOpCount, m_v_cvt_f32_i32); break;
  case kUIToFP: unary(kMOpCount, m_v_cvt_f32_u32); break;
  case kFPTrunc: unary(kMOpCount, m_v_cvt_f16_f32); break;
  case kFPExt: unary(kMOpCount, m_v_cvt_f32_f16); break;
  case kBitcast: r = Val(n.a); break;
  case kSelect: {
    const Cls c = ClassOf(i);
    if (c.cls == kSgpr) {
      const uint32_t t = S(n.a), fl = S(n.b);
      Scc(Val(n.c));
      const uint32_t d = NewTemp(kSgpr, c.size);
      Push(c.size == 2 ? m_s_cselect_b64 : m_s_cselect_b32, d, t, fl);
      r = OTemp(d);
    } else {
      r = Valu(m_v_cndmask_b32, Val(n.b), Val(n.a), kONone, 0, kVgpr, 1, Mask(n.c));
    }
    break;
  }
  case kExtract: { // p_split_vector component: a copy the allocator coalesces in place
    const uint32_t agg = Val(n.a);
    if (!IsTempOp(agg)) { r = agg; break; }
    const uint8_t cls = T(agg).cls; // by value: NewTemp may reallocate the temporaries
    const uint32_t d = NewTemp(cls, 1), sub = SubOf(agg) + (n.imm & 3);
    m_.temps[d].hint = 0x80000000u | sub << 24 | TempOf(agg);
    Push(cls == kSgpr ? m_s_mov_b32 : m_v_mov_b32, d, OTemp(TempOf(agg), sub));
    r = OTemp(d);
    break;
  }
  case kDescLoad: break; // rematerialized at its uses (Desc)
  case kLoadUbo: case kLoadUboX4: {
    const bool x4 = op == kLoadUboX4;
    const Node &off = f_.nodes[n.b];
    if (u) {
      const uint32_t h = Val(n.a), soff = IsConst(off) ? kONone : S(n.b); // sequenced: both may emit
      const uint32_t d = NewTemp(kSgpr, x4 ? 4 : 1);
      const uint32_t mi = Push(x4 ? m_s_buffer_load_dwordx4 : m_s_buffer_load_dword, d, h, soff);
      code_[mi].imm = (uint16_t)(((IsConst(off) ? (uint32_t)off.val : 0) + n.imm) & 0xFFFF);
      code_[mi].flags = kMfOffset;
      r = OTemp(d);
    } else {
      const uint32_t addr = V(n.b), h = Val(n.a);
      const uint32_t d = NewTemp(kVgpr, x4 ? 4 : 1);
      const uint32_t mi = Push(x4 ? m_buffer_load_dwordx4 : m_buffer_load_dword, d, addr, h);
      code_[mi].imm = (uint16_t)(n.imm & 0xFFF);
      code_[mi].flags = kMfOffen;
      r = OTemp(d);
    }
    break;
  }
  case kInterp: {
    const uint32_t attr = (uint32_t)(IsConst(f_.nodes[n.a]) ? f_.nodes[n.a].val & 31 : 0);
    const uint32_t chan = (uint32_t)(IsConst(f_.nodes[n.b]) ? f_.nodes[n.b].val & 3 : 0);
    const uint32_t t = NewTemp(kVgpr, 1), d = NewTemp(kVgpr, 1);
    code_[Push(m_v_interp_p1_f32, t, bary_[0])].imm = (uint16_t)(attr << 2 | chan);
    code_[Push(m_v_interp_p2_f32, d, bary_[1], OTemp(t))].imm = (uint16_t)(attr << 2 | chan);
    r = OTemp(d);
    break;
  }
  case kImageSample: case kImageLoad: {
    const uint32_t coord = NewTemp(kVgpr, 2);
    const uint32_t x = Val(n.b), y = Val(n.c);
    Push(m_p_create_vector, coord, x, y);
    const uint32_t d = NewTemp(kVgpr, 4);
    const uint32_t h = Val(n.a);
    const uint32_t mi = op == kImageSample ? Push(m_image_sample, d, OTemp(coord), h, Sampler(n.a))
                                           : Push(m_image_load, d, OTemp(coord), h);
    code_[mi].imm = 0xF; // dmask
    r = OTemp(d);
    break;
  }
  case kLoadSsbo: {
    const uint32_t d = NewTemp(kVgpr, 4);
    const uint32_t addr = V(n.b), h = Val(n.a);
    const uint32_t mi = Push(m_buffer_load_dwordx4, d, addr, h);
    code_[mi].imm = (uint16_t)(n.imm & 0xFFF);
    code_[mi].flags = kMfOffen;
    r = OTemp(d);
    break;
  }
  case kStoreSsbo: {
    const uint32_t data = V(n.c), addr = V(n.b); // sequenced: both may emit moves
    const uint32_t h = Val(n.a);
    const uint32_t mi = Push(m_buffer_store_dword, kONone, data, addr, h);
    code_[mi].imm = (uint16_t)(n.imm & 0xFFF);
    code_[mi].flags = kMfOffen;
    break;
  }
  case kExport: {
    const uint32_t k = (uint32_t)(IsConst(f_.nodes[n.a]) ? f_.nodes[n.a].val & 3 : 0);
    exports_[k] = V(n.b);
    break;
  }
  case kThreadId: r = tid_[IsConst(f_.nodes[n.a]) ? f_.nodes[n.a].val % 3 : 0]; break;
  case kGroupId: r = grp_; break;
  default: // not expected after lowering: plain move
    r = n.type == kVoid || n.a == kNone ? kONone : ToV(Val(n.a));
    f_.st.unselected++;
    break;
  }
  if (r != kONone && IsTempOp(r) && ClassOf(i).cls == kSgpr && IsV(r)) r = ToS(r); // p_as_uniform
  n.reg = r;
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

// Machine block of the edge from -> to (a split critical edge, or `to`).
uint32_t Isel::Target(uint32_t from, uint32_t to) const {
  for (uint32_t k = m_.blockOf[from] + 1; k < m_.blocks.size() && m_.blocks[k].ir == kNone; ++k)
    if (m_.blocks[k].phiFrom[0] == from && m_.blocks[k].phiFrom[1] == to) return k;
  return m_.blockOf[to];
}

void Isel::Terminator(uint32_t b) {
  const Block &blk = f_.blocks[b];
  MBlock &mb = m_.blocks[cur_];
  FlushExports(blk.succ[0] == kNone);
  mb.term = (uint32_t)code_.size();
  node_ = kNone;
  const uint32_t next = cur_ + 1;
  auto branch = [&](uint32_t op, uint32_t target) {
    const uint32_t mi = Push(op, kONone);
    code_[mi].aux = target;
  };
  if (blk.succ[0] == kNone) {
    Push(m_s_endpgm, kONone);
    mb.succ[0] = mb.succ[1] = kNone;
    return;
  }
  const bool two = blk.cond != kNone && blk.succ[1] != kNone;
  if (two && !IsConst(f_.nodes[blk.cond])) {
    const uint32_t tt = Target(b, blk.succ[0]), tf = Target(b, blk.succ[1]);
    Scc(Val(blk.cond)); // M2: divergent conditions branch on any active lane
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

// Machine block layout: IR blocks in order, each followed by the split
// critical edges into its successors' phis.
void Isel::Layout() {
  m_.blocks.clear();
  m_.blockOf.assign(f_.nblocks, kNone);
  auto hasPhis = [&](uint32_t s) { return f_.blocks[s].head != kNone && IsPhi(f_.nodes[f_.blocks[s].head]); };
  for (uint32_t b = 0; b < f_.nblocks; ++b) {
    const Block &blk = f_.blocks[b];
    if (blk.rpo == kNone) continue;
    MBlock mb{};
    mb.ir = b;
    mb.succ[0] = mb.succ[1] = mb.phiFrom[0] = mb.phiFrom[1] = kNone;
    m_.blockOf[b] = (uint32_t)m_.blocks.size();
    m_.blocks.push_back(mb);
    if (blk.cond == kNone || blk.succ[1] == kNone || IsConst(f_.nodes[blk.cond])) continue;
    for (uint32_t k = 2; k-- > 0;) { // false edge first: it falls through
      const uint32_t s = blk.succ[k];
      if (f_.blocks[s].npred < 2 || !hasPhis(s)) continue;
      MBlock eb{};
      eb.ir = kNone;
      eb.succ[1] = kNone;
      eb.phiFrom[0] = b;
      eb.phiFrom[1] = s;
      m_.blocks.push_back(eb);
    }
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
  Layout();
  std::vector<uint32_t> &phis = m_.work;
  phis.clear();
  for (uint32_t mbi = 0; mbi < m_.blocks.size(); ++mbi) {
    MBlock &mb = m_.blocks[mbi];
    cur_ = mbi;
    nsamp_ = ndesc_ = 0;
    mb.start = (uint32_t)code_.size();
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
      SelectNode(i);
    }
    Terminator(mb.ir);
    mb.end = (uint32_t)code_.size();
  }
  // Predecessors, then phi operands in predecessor order (back edges are
  // selected by now).
  for (MBlock &mb : m_.blocks) mb.npred = 0;
  for (uint32_t b = 0; b < m_.blocks.size(); ++b)
    for (uint32_t s : m_.blocks[b].succ)
      if (s != kNone && m_.blocks[s].npred < 2) m_.blocks[s].pred[m_.blocks[s].npred++] = b;
  for (uint32_t pi : phis) { // code_ indexed per access: Val may append instructions
    const uint32_t node = code_[pi].node, blk = code_[pi].block;
    const Node &n = f_.nodes[node];
    const uint32_t np = std::min<uint32_t>(m_.blocks[blk].npred, 2);
    for (uint32_t k = 0; k < np; ++k) {
      const MBlock &p = m_.blocks[m_.blocks[blk].pred[k]];
      const uint32_t irPred = p.ir == kNone ? p.phiFrom[0] : p.ir;
      const uint32_t o = Val(f_.phiPred[node] == irPred ? n.a : n.b);
      code_[pi].ops[k] = o;
      if (IsTempOp(o)) m_.temps[TempOf(o)].uses++;
    }
    code_[pi].nops = (uint8_t)np;
  }
  f_.st.literals += m_.scratch.size();
}
} // namespace

void SelectInstructions(Fn &f, Mach &m) {
  Isel isel(f, m);
  isel.Run();
}
} // namespace simv5
