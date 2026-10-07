// WorkloadRealisticV5Corpus.cpp - Deterministic shader corpus for realistic V5:
// thousands of typed DXIL-like shaders (pixel and compute; float math, integer
// addressing, texture / constant-buffer / buffer access, structured control
// flow with if/else, counted and data-dependent loops) encoded as LLVM-style
// programs (WorkloadRealisticV5Gen.h); WorkloadRealisticV5Encode.cpp encodes
// them as LLVM-style bitstreams and builds the shared corpus. Generation is
// not part of the timed work model; ReadShader (WorkloadRealisticV5Front.cpp)
// decodes it.
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Gen.h"
#include <cstring>
#ifdef SIMV5_VALIDATE_TRACE
#include <cstdio>
#endif
#include <vector>

namespace simv5 {
namespace {
constexpr uint32_t kMaxDepth = 5; // control-flow nesting
constexpr uint32_t kPending = 12; // unused values of open expression trees (per type)
constexpr uint32_t kSpecI32 = 4;  // pipeline-state constants 0..3 are i32, 4..7 f32

// Operand forms of the generated instructions (operand types, constant kinds).
enum Form : uint8_t {
  fF2, fF2Clamp, fF1, fF3, fFCmp, fI2, fIShift, fIMask, fIDiv, fI1, fI3, fIBfe, fICmp,
  fSelF, fSelI, fIToF, fFToI, fBitFI, fBitIF, fZExtB, fBoolOp, fSample, fCBuf, fTexLoad,
  fBufLoad, fBufStore,
};
struct Choice {
  uint8_t op, form, pixel, compute; // weights per shader kind
};
constexpr Choice kChoices[] = {
    {kFMul, fF2, 12, 6}, {kFAdd, fF2, 10, 5}, {kFMad, fF3, 10, 5}, {kFSub, fF2, 3, 2},
    {kFMax, fF2Clamp, 2, 1}, {kFMin, fF2Clamp, 2, 1}, {kSaturate, fF1, 3, 1}, {kFAbs, fF1, 1, 1},
    {kSqrt, fF1, 1, 1}, {kRsqrt, fF1, 2, 1}, {kExp, fF1, 1, 0}, {kLog, fF1, 1, 0},
    {kSin, fF1, 1, 0}, {kCos, fF1, 1, 0}, {kFrc, fF1, 1, 1}, {kRoundNi, fF1, 1, 1},
    {kFDiv, fF2, 1, 1}, {kFCmpOlt, fFCmp, 2, 1}, {kFCmpOge, fFCmp, 1, 1}, {kFCmpOgt, fFCmp, 1, 0},
    {kIAdd, fI2, 4, 10}, {kIMul, fI2, 1, 4}, {kISub, fI2, 1, 2}, {kShl, fIShift, 1, 4},
    {kLShr, fIShift, 1, 4}, {kAShr, fIShift, 0, 1}, {kAnd, fIMask, 2, 5}, {kOr, fIMask, 1, 3},
    {kXor, fIMask, 1, 2}, {kUDiv, fIDiv, 0, 1}, {kURem, fIDiv, 0, 1}, {kUbfe, fIBfe, 1, 2},
    {kIMad, fI3, 1, 3}, {kUMin, fI2, 1, 2}, {kIMax, fI2, 0, 1}, {kCountbits, fI1, 0, 1},
    {kFirstbitHi, fI1, 0, 1}, {kICmpUlt, fICmp, 1, 3}, {kICmpEq, fICmp, 1, 2}, {kICmpSlt, fICmp, 0, 1},
    {kSelect, fSelF, 3, 1}, {kSelect, fSelI, 1, 2}, {kSIToFP, fIToF, 1, 2}, {kUIToFP, fIToF, 1, 1},
    {kFPToSI, fFToI, 1, 1}, {kFPToUI, fFToI, 1, 1}, {kBitcast, fBitFI, 1, 1}, {kBitcast, fBitIF, 1, 1},
    {kZExt, fZExtB, 1, 1}, {kAnd, fBoolOp, 1, 1}, {kSample, fSample, 3, 1}, {kCBufferLoad, fCBuf, 1, 1},
    {kTextureLoad, fTexLoad, 1, 1}, {kBufferLoad, fBufLoad, 0, 3}, {kBufferStore, fBufStore, 0, 1},
};
constexpr uint32_t kNumChoices = sizeof(kChoices) / sizeof(kChoices[0]);

inline uint32_t TySlot(uint32_t ty) { return ty == kF32 ? 0 : ty == kI32 ? 1 : 2; }

// Generates one shader as a structured, typed SSA program, then encodes it.
class ShaderGen {
public:
  ShaderGen(uint64_t seed, uint32_t values) : rng_(seed) {
    compute_ = (Next(rng_) % 5) < 2;
    for (uint32_t k = 0; k < kNumChoices; ++k) {
      totalWeight_ += compute_ ? kChoices[k].compute : kChoices[k].pixel;
      cumWeight_[k] = totalWeight_;
    }
    BuildConstants(values);
    cur_ = NewLabel();
    Start(cur_);
    EmitPrologue(values);
    GenRegion(0, values > Used() + 64 ? values - Used() - 32 : 32);
    EmitEpilogue();
    insts_.push_back({kRet});
    CountUnused();
  }
  void Export(Program &p) {
    p.consts = std::move(consts_);
    p.insts = std::move(insts_);
    p.labels = std::move(labels_);
    p.nconst = nconst_;
    p.nblocks = nblocks_;
    p.unused = unused_;
    p.nameSeed = rng_;
    std::memcpy(p.dxop, dxop_, sizeof(dxop_));
  }

private:
  struct Recipe {
    uint32_t id;
    WInst in;
  };
  struct Scope {
    size_t pool[3];
    uint32_t pending[3][kPending];
    uint32_t np[3];
  };
  // --- constants (LLVM constant pool: ints, floats, pipeline-state constants)
  uint32_t AddConst(uint8_t ty, uint32_t bits, int8_t spec = -1) {
    if (spec < 0)
      for (uint32_t k = 0; k < consts_.size(); ++k)
        if (consts_[k].ty == ty && consts_[k].spec < 0 && consts_[k].bits == bits) return k;
    consts_.push_back({ty, spec, bits});
    return (uint32_t)consts_.size() - 1;
  }
  void BuildConstants(uint32_t values) {
    // Grouped by type (one SETTYPE each): i32 first, then f32. Ids are
    // assigned in this order; constant ids precede all instruction values.
    for (int8_t k = 0; k < (int8_t)kSpecI32; ++k) AddConst(kI32, 0, k);
    for (uint32_t op = 0; op < kOpCount; ++op) {
      if (Info(op).rec != kRecCall) continue;
      dxop_[op] = AddConst(kI32, Info(op).code);
      ndxop_++;
    }
    for (uint32_t v : {0u, 1u, 2u, 3u, 4u, 8u, 16u, 31u, 255u, 0xFFFFu, 0x3FFu, 0xFFu << 8})
      AddConst(kI32, v);
    for (uint32_t k = 0, e = 8 + values / 128; k < e; ++k) {
      const uint64_t r = Next(rng_);
      AddConst(kI32, (r & 1) ? (uint32_t)((r >> 8) % 64) + 5 : (uint32_t)(r >> 20));
    }
    firstFloat_ = (uint32_t)consts_.size();
    for (int8_t k = kSpecI32; k < (int8_t)kSpecConsts; ++k) AddConst(kF32, 0, k);
    for (float v : {0.0f, 1.0f, 0.5f, 2.0f, 0.25f, -1.0f, 4.0f, 0.125f})
      AddConst(kF32, (uint32_t)F32Bits(v));
    for (uint32_t k = 0, e = 8 + values / 64; k < e; ++k) {
      const uint64_t r = Next(rng_);
      const float v = (float)((int32_t)(r % 8193) - 4096) * (1.0f / 1024.0f) + 0.0078125f;
      AddConst(kF32, (uint32_t)F32Bits(v));
    }
    nconst_ = next_ = (uint32_t)consts_.size();
    vty_.resize(nconst_);
    cd_.assign(nconst_, 1);
    for (uint32_t k = 0; k < nconst_; ++k) vty_[k] = consts_[k].ty;
  }
  uint32_t IntConst(uint32_t v) { return Lookup(kI32, v); }
  uint32_t FloatConst(float v) { return Lookup(kF32, (uint32_t)F32Bits(v)); }
  uint32_t Lookup(uint8_t ty, uint32_t bits) {
    for (uint32_t k = 0; k < nconst_; ++k)
      if (consts_[k].ty == ty && consts_[k].spec < 0 && consts_[k].bits == bits) return k;
    return ty == kF32 ? firstFloat_ + kSpecConsts - kSpecI32 : kSpecI32; // first plain constant
  }
  // Plain constants without the leading identities (0 / 1, 0.0 / 1.0).
  uint32_t RandomConst(uint8_t ty, uint64_t q) {
    const uint32_t lo = ty == kF32 ? firstFloat_ + (kSpecConsts - kSpecI32) + 2 : kSpecI32 + ndxop_ + 2;
    const uint32_t hi = ty == kF32 ? nconst_ : firstFloat_;
    return lo + (uint32_t)(q % (hi - lo));
  }
  // Constant kinds typical for each operand form (DXC already folded the
  // identities, so x*1, x+0 do not appear; masks and shifts are immediates).
  uint32_t FormConst(uint32_t form, uint64_t q) {
    static constexpr uint32_t kShifts[] = {1, 2, 3, 4, 8, 16, 24, 31};
    static constexpr uint32_t kMasks[] = {1, 3, 0xFF, 0xFFFF, 0x3FF, 0xFF00, 31, 0x7FFFFFFF};
    static constexpr uint32_t kDivs[] = {3, 5, 6, 7, 10, 12, 24, 100};
    switch (form) {
    case fF2Clamp: return FloatConst((q & 1) ? 0.0f : 1.0f);
    case fFCmp: return FloatConst((q & 3) == 0 ? 0.5f : (q & 1) ? 0.0f : 1.0f);
    case fIShift: return IntConst(kShifts[q & 7]);
    case fIMask: return IntConst(kMasks[q & 7]);
    case fIDiv: return IntConst(kDivs[q & 7]);
    case fICmp: return IntConst((q & 1) ? 0u : (uint32_t)(q % 64));
    case fI2: case fI3: return RandomConst(kI32, q >> 4);
    default: return RandomConst(kF32, q >> 4);
    }
  }
  // --- labels and values
  uint32_t NewLabel() {
    labels_.push_back(kNone);
    return (uint32_t)labels_.size() - 1;
  }
  void Start(uint32_t label) {
    labels_[label] = nblocks_++;
    cur_ = label;
  }
  Scope Save() const {
    Scope s;
    for (uint32_t t = 0; t < 3; ++t) {
      s.pool[t] = pool_[t].size();
      std::memcpy(s.pending[t], pending_[t], sizeof(pending_[t]));
      s.np[t] = np_[t];
    }
    return s;
  }
  void Restore(const Scope &s) {
    for (uint32_t t = 0; t < 3; ++t) {
      pool_[t].resize(s.pool[t]);
      std::memcpy(pending_[t], s.pending[t], sizeof(pending_[t]));
      np_[t] = s.np[t];
    }
  }
  uint32_t Used() const { return next_; }
  uint32_t Last(uint8_t ty) { return pool_[TySlot(ty)].empty() ? EnsureValue(ty) : pool_[TySlot(ty)].back(); }
  // Appends an instruction; value-producing ones get the next value id (LLVM
  // numbers only non-void values).
  uint32_t Push(WInst in, bool track = true) {
#ifdef SIMV5_VALIDATE_TRACE
    if (in.kind == kInst && (Info(in.op).rec == kRecBinop || Info(in.op).rec == kRecCmp) && vty_[in.a] != vty_[in.b])
      std::fprintf(stderr, "corpus: op %u operand types %u/%u (values %u/%u, next %u)\n", in.op, vty_[in.a],
                   vty_[in.b], in.a, in.b, next_);
#endif
    insts_.push_back(in);
    if (in.kind == kInst && Info(in.op).ty == kVoid) return kNone;
    const uint32_t id = next_++;
    vty_.push_back(in.ty);
    cd_.push_back(ConstDerived(in));
    if (track && (in.ty == kF32 || in.ty == kI32 || in.ty == kI1)) {
      const uint32_t t = TySlot(in.ty);
      pool_[t].push_back(id);
#ifdef SIMV5_VALIDATE_TRACE
      if (in.kind == kPhi && np_[t] == kPending) std::fprintf(stderr, "corpus: phi %u with full pending%c", id, 10);
#endif
      MakeRoom(t, 1);
      pending_[t][np_[t]++] = id;
    }
    return id;
  }
  uint32_t Inst(uint32_t op, uint8_t ty, uint32_t a, uint32_t b = kNone, uint32_t c = kNone, uint8_t imm = 0) {
    WInst in{kInst};
    in.op = (uint8_t)op;
    in.ty = ty;
    in.imm = imm;
    in.a = a;
    in.b = b;
    in.c = c;
    return Push(in, ty != kHandle && !IsResRet(ty));
  }
  // DXC output has no dead code: count instruction values without a use
  // (resource handles excluded: root-signature ranges may stay unused).
  void CountUnused() {
    std::vector<uint8_t> used(next_, 0);
    std::vector<uint32_t> def(next_, 0);
    uint32_t id = nconst_;
    for (const WInst &in : insts_) {
      for (uint32_t v : {in.a, in.b, in.c})
        if (v != kNone && v < next_) used[v] = 1;
      if (in.kind == kPhi || (in.kind == kInst && Info(in.op).ty != kVoid)) def[id++] = in.kind == kPhi ? kOpCount : in.op;
    }
    for (uint32_t v = nconst_; v < next_; ++v) {
      if (used[v] || def[v] == kCreateHandle) continue;
      unused_++;
#ifdef SIMV5_VALIDATE_TRACE
      std::fprintf(stderr, "unused: value %u op %u%c", v, def[v], 10);
#endif
    }
  }
  // The value derives from constants only (pipeline-state constants included):
  // the driver folds it. Loop phis (back edge unknown yet) count as variable.
  bool ConstDerived(const WInst &in) const {
    if (in.kind == kPhi) return in.b != kNone && cd_[in.a] && cd_[in.b];
    if (in.kind != kInst || !HasFlag(in.op, kPure) || HasFlag(in.op, kMemRead | kDivSource | kNoFold)) return false;
    for (uint32_t v : {in.a, in.b, in.c})
      if (v != kNone && !cd_[v]) return false;
    return true;
  }
  // Pick for a branch condition operand: DXC folds constant expressions, so
  // only pipeline-state bits (PickCond) make a branch foldable. A constant-
  // derived pick stays pending; a shader input replaces it.
  uint32_t PickVar(uint8_t ty, uint64_t q) {
    const uint32_t t = TySlot(ty), np = np_[t];
    const uint32_t v = Pick(ty, q);
    if (!cd_[v]) return v;
    if (np_[t] + 1 == np && pending_[t][np_[t]] == v) ++np_[t]; // popped: put it back
    const std::vector<uint32_t> &in = ty == kF32 ? inputsF_ : inputsI_;
    return in[(q >> 24) % in.size()];
  }
  // Joins two open expression trees of type slot t (the result is pending).
  uint32_t Combine(uint32_t t, uint32_t x, uint32_t y) {
    const uint32_t h = (uint32_t)Mix(((uint64_t)x << 32) | y) & 7;
    if (t == 0) return Inst(h < 5 ? kFAdd : h < 7 ? kFMul : kFMax, kF32, x, y);
    if (t == 1) return Inst(h < 4 ? kIAdd : h < 6 ? kXor : kOr, kI32, x, y);
    return Inst((h & 1) ? kAnd : kOr, kI1, x, y);
  }
  // Full pending stack: the two oldest open trees join (no value is dropped).
  // Phis cannot do this (no instruction may sit between phis), so blocks that
  // start with phis make room before their branch.
  void MakeRoom(uint32_t t, uint32_t n) {
    while (np_[t] + n > kPending) {
      const uint32_t x = pending_[t][0], y = pending_[t][1];
      std::memmove(pending_[t], pending_[t] + 2, (kPending - 2) * sizeof(uint32_t));
      np_[t] -= 2;
      Combine(t, x, y);
    }
  }
  // Pending values of slot t defined at or after value id `start` (pending
  // ids increase, so they form the top of the stack).
  uint32_t NewPending(uint32_t t, uint32_t start) const {
    uint32_t k = np_[t];
    while (k && pending_[t][k - 1] >= start) --k;
    return np_[t] - k;
  }
  void Join(uint32_t t, uint32_t start) {
    while (NewPending(t, start) >= 2) {
      const uint32_t y = pending_[t][--np_[t]], x = pending_[t][--np_[t]];
      Combine(t, x, y);
    }
  }
  // DXC output has no dead code: before a scope ends (if arm, shader end) its
  // open expression trees join into one value per type, which the merge phis
  // or outputs consume; a leftover condition selects between float values.
  void Reduce(uint32_t start) {
    Join(2, start);
    if (NewPending(2, start)) {
      const uint32_t c = pending_[2][--np_[2]], a = Last(kF32), b = Pick(kF32, Next(rng_));
      Inst(kSelect, kF32, a, b != a ? b : FloatConst(0.0f), c);
    }
    Join(1, start);
    Join(0, start);
  }
  // A value of type ty must exist (pools can be empty early in a region).
  uint32_t EnsureValue(uint8_t ty) {
    if (ty == kI1) return Inst(kFCmpOlt, kI1, Last(kF32), FloatConst(0.5f));
    if (ty == kI32) return Inst(kFPToSI, kI32, Last(kF32));
    return Inst(kSIToFP, kF32, Last(kI32));
  }
  uint32_t Pick(uint8_t ty, uint64_t q) {
    const uint32_t v = PickImpl(ty, q);
#ifdef SIMV5_VALIDATE_TRACE
    if (vty_[v] != ty) {
      std::fprintf(stderr, "pick: want %u got %u (value %u) np %u pool %zu" "%c", ty, vty_[v], v, np_[TySlot(ty)], pool_[TySlot(ty)].size(), 10);
      for (uint32_t k = 0; k < np_[TySlot(ty)]; ++k) std::fprintf(stderr, " pending %u type %u%c", pending_[TySlot(ty)][k], vty_[pending_[TySlot(ty)][k]], 10);
    }
#endif
    return v;
  }
  uint32_t PickImpl(uint8_t ty, uint64_t q) {
    const uint32_t t = TySlot(ty);
    if (pool_[t].empty()) return EnsureValue(ty);
    if (ty != kI1 && ((q >> 58) & 31) == 0) return ty == kI32 ? (uint32_t)((q >> 8) % kSpecI32)
                                                              : firstFloat_ + (uint32_t)((q >> 8) % (kSpecConsts - kSpecI32));
    if (np_[t] && ((q >> 6) & 3) != 0) return pending_[t][--np_[t]];
    const std::vector<uint32_t> &p = pool_[t];
    if ((q >> 5) & 7) return p[p.size() - std::min<size_t>(1 + ((q >> 12) & 15), p.size())];
    if ((q >> 44) & 3) return p[p.size() - std::min<size_t>(1 + (size_t)((q >> 20) % 64), p.size())];
    const std::vector<uint32_t> &in = ty == kF32 ? inputsF_ : inputsI_;
    if (ty != kI1 && !in.empty()) return in[(q >> 20) % in.size()];
    return p[(q >> 20) % p.size()];
  }
  uint32_t PickNot(uint8_t ty, uint64_t q, uint32_t other) {
    const uint32_t v = Pick(ty, q);
    return v != other ? v : Pick(ty, Mix(q));
  }
  void Extracts(uint32_t agg, uint8_t compTy, uint64_t r) {
    const uint32_t n = 1 + (uint32_t)(r % 4);
    for (uint32_t k = 0; k < n; ++k) Inst(kExtract, compTy, agg, kNone, kNone, (uint8_t)((k + (r >> 4)) & 3));
  }
  uint32_t Handle(const std::vector<uint32_t> &set, uint64_t q) { return set[q % set.size()]; }

  void EmitPrologue(uint32_t values) {
    // Resource handles (root signature ranges), then inputs and constant buffers.
    const uint64_t r = Next(rng_);
    const uint32_t ncb = 1 + (uint32_t)(r % 3), ntex = 2 + (uint32_t)((r >> 8) % 7);
    const uint32_t nbuf = compute_ ? 1 + (uint32_t)((r >> 16) % 4) : (uint32_t)((r >> 16) % 2);
    uint32_t range = 0;
    auto handles = [&](std::vector<uint32_t> &set, uint32_t count) {
      for (uint32_t k = 0; k < count; ++k) set.push_back(Inst(kCreateHandle, kHandle, IntConst(range++), IntConst(0)));
    };
    handles(cbufs_, ncb);
    handles(texs_, ntex);
    handles(bufs_, nbuf);
    if (compute_) {
      for (uint32_t k = 0; k < 3; ++k) inputsI_.push_back(Inst(kThreadId, kI32, IntConst(k)));
      inputsI_.push_back(Inst(kGroupId, kI32, IntConst(0)));
    } else {
      for (uint32_t k = 0, e = 4 + std::min(20u, values / 256); k < e; ++k)
        inputsF_.push_back(Inst(kLoadInput, kF32, IntConst(k / 4), IntConst(k & 3)));
    }
    for (uint32_t k = 0, e = 2 + (uint32_t)((r >> 24) % 5); k < e; ++k) {
      const uint64_t q = Next(rng_);
      const uint8_t ty = (q & 3) ? kF32 : kI32;
      const uint32_t agg = Inst(kCBufferLoad, ty == kF32 ? kResRetF32 : kResRetI32,
                                Handle(cbufs_, q >> 8), IntConst((uint32_t)((q >> 16) % 16)));
      const size_t before = pool_[TySlot(ty)].size();
      Extracts(agg, ty, q >> 24);
      for (size_t j = before; j < pool_[TySlot(ty)].size(); ++j)
        (ty == kF32 ? inputsF_ : inputsI_).push_back(pool_[TySlot(ty)][j]);
    }
    if (inputsF_.empty()) inputsF_.push_back(Inst(kSIToFP, kF32, inputsI_[0]));
    if (inputsI_.empty()) inputsI_.push_back(Inst(kFPToSI, kI32, inputsF_[0]));
  }
  void EmitEpilogue() {
    // Outputs consume all open expression trees (DXIL has no dead code).
    Reduce(0);
    if (np_[1]) Inst(kSIToFP, kF32, pending_[1][--np_[1]]);
    Join(0, 0);
    const uint32_t acc = np_[0] ? pending_[0][--np_[0]] : Last(kF32);
    if (compute_) {
      for (uint32_t k = 0; k < 2; ++k)
        Inst(kBufferStore, kF32, Handle(bufs_, k), inputsI_[0], k ? Last(kF32) : acc);
    } else {
      for (uint32_t k = 0; k < 4; ++k) Inst(kStoreOutput, kF32, IntConst(k), k ? Pick(kF32, Next(rng_)) : acc);
    }
  }

  void EmitInst() {
    const uint64_t r = Next(rng_);
    if (((r >> 3) & 63) == 0 && !pool_[0].empty()) { // redundancy exposed by lowering
      // Repeat a visible value's recipe (its operands are visible too).
      const std::vector<uint32_t> &p = pool_[0];
      const uint32_t src = p[p.size() - 1 - (size_t)((r >> 52) % std::min<size_t>(p.size(), 64))];
      for (const Recipe &d : recent_) {
        if (d.id == src) {
#ifdef SIMV5_VALIDATE_TRACE
          std::fprintf(stderr, "dup: op %u src %u type %u next %u%c", d.in.op, src, vty_[src], next_, 10);
#endif
          Push(d.in);
          return;
        }
      }
    }
    const uint32_t pick = (uint32_t)((r >> 20) % totalWeight_);
    uint32_t k = 0;
    while (cumWeight_[k] <= pick) ++k;
    const Choice &ch = kChoices[k];
    const uint64_t q0 = Next(rng_), q1 = Next(rng_), q2 = Next(rng_);
    const bool cst = (q2 & 3) == 0; // constant in the last value slot
    uint32_t id = kNone;
    switch (ch.form) {
    case fF2: {
      const uint32_t a = Pick(kF32, q0);
      const uint32_t b = cst ? FormConst(fF2, q1) : (ch.op == kFMul ? Pick(kF32, q1) : PickNot(kF32, q1, a));
      id = Inst(ch.op, kF32, a, b);
      break;
    }
    case fF2Clamp: {
      const uint32_t a = Pick(kF32, q0);
      id = Inst(ch.op, kF32, a, (q2 & 1) ? FormConst(fF2Clamp, q1) : PickNot(kF32, q1, a));
      break;
    }
    case fF1: id = Inst(ch.op, kF32, Pick(kF32, q0)); break;
    case fF3: { // operands picked in order (argument evaluation order is unspecified)
      const uint32_t a = Pick(kF32, q0);
      const uint32_t b = cst ? FormConst(fF2, q1) : Pick(kF32, q1);
      const uint32_t c = (q2 & 12) == 0 ? FormConst(fF2, q2 >> 8) : Pick(kF32, q2);
      id = Inst(ch.op, kF32, a, b, c);
      break;
    }
    case fFCmp: {
      const uint32_t a = Pick(kF32, q0);
      id = Inst(ch.op, kI1, a, (q2 & 1) ? FormConst(fFCmp, q1) : PickNot(kF32, q1, a));
      break;
    }
    case fI2: {
      const uint32_t a = Pick(kI32, q0);
      id = Inst(ch.op, kI32, a, (q2 % 3) == 0 ? FormConst(fI2, q1) : PickNot(kI32, q1, a));
      break;
    }
    case fIShift: case fIMask: {
      const uint32_t a = Pick(kI32, q0);
      id = Inst(ch.op, kI32, a, (q2 & 3) ? FormConst(ch.form, q1) : PickNot(kI32, q1, a));
      break;
    }
    case fIDiv: id = Inst(ch.op, kI32, Pick(kI32, q0), FormConst(fIDiv, q1)); break;
    case fI1: id = Inst(ch.op, kI32, Pick(kI32, q0)); break;
    case fI3: {
      const uint32_t a = Pick(kI32, q0);
      const uint32_t b = cst ? FormConst(fI3, q1) : Pick(kI32, q1);
      const uint32_t c = (q2 & 8) ? FormConst(fI3, q2 >> 8) : Pick(kI32, q2);
      id = Inst(ch.op, kI32, a, b, c);
      break;
    }
    case fIBfe:
      id = Inst(ch.op, kI32, IntConst(1u + (uint32_t)(q1 % 16)), IntConst((uint32_t)((q1 >> 8) % 16)), Pick(kI32, q0));
      break;
    case fICmp: {
      const uint32_t a = Pick(kI32, q0);
      id = Inst(ch.op, kI1, a, (q2 & 1) ? FormConst(fICmp, q1) : PickNot(kI32, q1, a));
      break;
    }
    case fSelF: case fSelI: {
      const uint8_t ty = ch.form == fSelF ? kF32 : kI32;
      const uint32_t c = Pick(kI1, q2), a = Pick(ty, q0);
      id = Inst(kSelect, ty, a, cst ? FormConst(ty == kF32 ? fF2Clamp : fICmp, q1) : PickNot(ty, q1, a), c);
      break;
    }
    case fIToF: id = Inst(ch.op, kF32, Pick(kI32, q0)); break;
    case fFToI: id = Inst(ch.op, kI32, Pick(kF32, q0)); break;
    case fBitFI: id = Inst(kBitcast, kI32, Pick(kF32, q0)); break;
    case fBitIF: id = Inst(kBitcast, kF32, Pick(kI32, q0)); break;
    case fZExtB: id = Inst(kZExt, kI32, Pick(kI1, q0)); break;
    case fBoolOp: {
      const uint32_t a = Pick(kI1, q0);
      id = Inst((q2 & 1) ? kAnd : kOr, kI1, a, PickNot(kI1, q1, a));
      break;
    }
    case fSample: {
      const uint32_t u = Pick(kF32, q0), v = Pick(kF32, q1);
      const uint32_t agg = Inst(kSample, kResRetF32, Handle(texs_, q2), u, v);
      Extracts(agg, kF32, q2 >> 8);
      return;
    }
    case fCBuf: {
      const uint8_t ty = (q2 & 3) ? kF32 : kI32;
      const uint32_t reg = (q2 & 0x70) ? IntConst((uint32_t)(q1 % 16)) : Pick(kI32, q1); // dynamic: arrays
      const uint32_t agg = Inst(kCBufferLoad, ty == kF32 ? kResRetF32 : kResRetI32, Handle(cbufs_, q0), reg);
      Extracts(agg, ty, q2 >> 8);
      return;
    }
    case fTexLoad: {
      const uint32_t x = Pick(kI32, q0), y = Pick(kI32, q1);
      const uint32_t agg = Inst(kTextureLoad, kResRetF32, Handle(texs_, q2), x, y);
      Extracts(agg, kF32, q2 >> 8);
      return;
    }
    case fBufLoad: case fBufStore: {
      if (bufs_.empty()) return;
      if (ch.form == fBufStore) {
        const uint32_t idx = Pick(kI32, q0), val = Pick(kF32, q1);
        Inst(kBufferStore, kF32, Handle(bufs_, q2), idx, val);
        return;
      }
      const uint8_t ty = (q2 & 1) ? kF32 : kI32;
      const uint32_t agg = Inst(kBufferLoad, ty == kF32 ? kResRetF32 : kResRetI32, Handle(bufs_, q2 >> 1), Pick(kI32, q0));
      Extracts(agg, ty, q2 >> 8);
      return;
    }
    }
    if (id != kNone) {
      if (recent_.size() == 64) recent_.erase(recent_.begin());
      recent_.push_back({id, insts_.back()});
    }
  }
  // Branch condition: a pipeline-state feature bit (folds per variant), or a
  // computed comparison.
  uint32_t PickCond() {
    const uint64_t q = Next(rng_);
    if ((q & 7) == 0) {
      const uint32_t bit = Inst(kAnd, kI32, (uint32_t)((q >> 4) % kSpecI32), IntConst(1u << ((q >> 8) % 4)));
      return Inst(kICmpNe, kI1, bit, IntConst(0));
    }
    if ((q & 8) && !pool_[2].empty()) {
      const uint32_t c = pool_[2][pool_[2].size() - 1 - (size_t)((q >> 8) % std::min<size_t>(pool_[2].size(), 4))];
      if (!cd_[c]) return c;
    }
    return Inst(kFCmpOlt, kI1, PickVar(kF32, q >> 12), FormConst(fFCmp, q >> 20));
  }
  void Branch(uint32_t label) {
    WInst in{kBr};
    in.t = label;
    insts_.push_back(in);
  }
  void CondBranch(uint32_t cond, uint32_t t, uint32_t f) {
    WInst in{kBrCond};
    in.c = cond;
    in.t = t;
    in.f = f;
    insts_.push_back(in);
  }
  uint32_t Phi(uint8_t ty, uint32_t a, uint32_t la, uint32_t b, uint32_t lb) {
    WInst in{kPhi};
    in.ty = ty;
    in.a = a;
    in.b = b;
    in.t = la;
    in.f = lb;
    return Push(in);
  }

  void GenRegion(uint32_t depth, uint32_t budget) {
    const uint32_t end = Used() + budget;
    while (Used() < end) {
      const uint32_t left = end - Used();
      const uint64_t r = Next(rng_);
      const uint32_t pick = (uint32_t)(r % 100);
      if (depth >= kMaxDepth || left < 48 || pick < 45) {
        for (uint32_t k = std::min<uint32_t>(left, 8 + (uint32_t)((r >> 8) % 40)); k; --k) EmitInst();
        continue;
      }
      const uint32_t sub = std::max<uint32_t>(4, left * (20 + (uint32_t)((r >> 16) % 40)) / 100);
      if (pick < 78) GenIf(depth, sub, r, pick >= 64);
      else GenLoop(depth, sub, r, pick < 90);
    }
  }
  void GenIf(uint32_t depth, uint32_t sub, uint64_t r, bool hasElse) {
    const uint32_t lthen = NewLabel(), lelse = hasElse ? NewLabel() : kNone, lmerge = NewLabel();
    const uint32_t pre = cur_;
    const uint32_t preF = Last(kF32), preI = Last(kI32);
    const uint32_t cond = PickCond(); // may push values: before making room
    MakeRoom(0, 1);                   // the merge phis (arms restore this pending state)
    MakeRoom(1, 1);
    CondBranch(cond, lthen, hasElse ? lelse : lmerge);
    uint32_t armVal[2][2] = {{preF, preI}, {preF, preI}}, armEnd[2] = {pre, pre};
    for (uint32_t arm = 0; arm < (hasElse ? 2u : 1u); ++arm) {
      Start(arm ? lelse : lthen);
      const Scope s = Save();
      const uint32_t start = next_;
      GenRegion(depth + 1, arm ? sub / 2 + 1 : sub);
      Reduce(start);
      armVal[arm][0] = Last(kF32);
      armVal[arm][1] = Last(kI32);
      armEnd[arm] = cur_;
      Branch(lmerge);
      Restore(s);
    }
    Start(lmerge);
    // One phi per type carries the arms' results (equal values: the phi folds).
    for (uint32_t t = 0; t < 2; ++t) Phi(t ? kI32 : kF32, armVal[0][t], armEnd[0], armVal[1][t], armEnd[1]);
  }
  // Counted loop (i32 induction variable, constant or uniform trip count) or a
  // data-dependent do-while loop; both carry float accumulators in phis.
  void GenLoop(uint32_t depth, uint32_t sub, uint64_t r, bool counted) {
    const uint32_t lhead = NewLabel(), lexit = NewLabel(), pre = cur_;
    const uint32_t init = counted ? IntConst(0) : kNone, accInit = Last(kF32);
    const uint32_t nacc = 1 + (uint32_t)((r >> 32) % 2);
    MakeRoom(0, nacc); // the header phis
    MakeRoom(1, 1);
    Branch(lhead);
    Start(lhead);
    const size_t firstPhi = insts_.size();
    uint32_t iv = kNone;
    if (counted) iv = Phi(kI32, init, pre, kNone, kNone);
    for (uint32_t p = 0; p < nacc; ++p) Phi(kF32, accInit, pre, kNone, kNone);
    if (counted && ((r >> 40) & 1)) Inst(kSIToFP, kF32, iv);
    GenRegion(depth + 1, sub);
    uint32_t cond;
    if (counted) {
      const uint32_t inext = Inst(kIAdd, kI32, iv, IntConst(1));
      const uint32_t trip = ((r >> 44) & 3) ? IntConst(2 + (uint32_t)((r >> 48) % 15)) : inputsI_[(r >> 48) % inputsI_.size()];
#ifdef SIMV5_VALIDATE_TRACE
      std::fprintf(stderr, "loop: iv %u inext %u trip %u types %u %u %u\n", iv, inext, trip, vty_[iv], vty_[inext], vty_[trip]);
#endif
      cond = Inst(kICmpUlt, kI1, inext, trip);
      insts_[firstPhi].b = inext;
      insts_[firstPhi].f = cur_;
    } else {
      cond = Inst(kFCmpOlt, kI1, PickVar(kF32, r >> 8), FormConst(fFCmp, r >> 20));
    }
    for (uint32_t p = 0; p < nacc; ++p) { // back-edge values (forward references)
      const std::vector<uint32_t> &fp = pool_[0];
      insts_[firstPhi + (counted ? 1 : 0) + p].b = fp[fp.size() - 1 - std::min<size_t>(p, fp.size() - 1)];
      insts_[firstPhi + (counted ? 1 : 0) + p].f = cur_;
    }
    CondBranch(cond, lhead, lexit);
    Start(lexit);
  }

  uint64_t rng_;
  bool compute_ = false;
  uint32_t totalWeight_ = 0, cumWeight_[kNumChoices] = {};
  uint32_t unused_ = 0;
  uint32_t nconst_ = 0, next_ = 0, nblocks_ = 0, cur_ = 0, firstFloat_ = 0, ndxop_ = 0;
  uint32_t dxop_[kOpCount] = {};
  std::vector<ConstDef> consts_;
  std::vector<uint8_t> vty_, cd_; // value type; constant-derived
  std::vector<uint32_t> pool_[3], labels_, inputsF_, inputsI_, cbufs_, texs_, bufs_;
  std::vector<WInst> insts_;
  std::vector<Recipe> recent_;
  uint32_t pending_[3][kPending] = {};
  uint32_t np_[3] = {};
};

} // namespace

void GenerateShader(uint64_t seed, uint32_t values, Program &out) {
  ShaderGen gen(seed, values);
  gen.Export(out);
}

} // namespace simv5
