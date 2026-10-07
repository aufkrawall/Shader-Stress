// WorkloadRealisticV5Fold.cpp - Realistic V5 constant folding and algebraic
// simplification (nir_opt_constant_folding / nir_opt_algebraic / InstCombine
// style): exact evaluation of every foldable DXIL operation (32-bit integer
// wrap-around, DXIL shift masking and division-by-zero results, IEEE single
// precision with one rounding per operation, saturating float-to-int), known
// bits for integers, a range lattice for floats (nir_range_analysis), and the
// rewrite rules that use them. Also node creation and constant uniquing.
//
// Bit-reproducibility: one IEEE operation per expression, FP contraction off,
// no transcendental folding (libm results differ between C runtimes).
#include "workloads/WorkloadRealisticV5.h"
#include "workloads/WorkloadRealisticV5Replica.h"
#include <cstdio>
#include <array>
#include <cmath>
#include <utility>
#if defined(__clang__)
#pragma clang fp contract(off)
#endif

namespace simv5 {
namespace {
// Float facts (Node::val of non-constant float values).
constexpr uint64_t kNotNaN = 1, kNonNeg = 2, kLe1 = 4, kSignClear = 8, kIntegral = 16;

inline float Fl(uint64_t v) { return AsF32(v); }
inline uint64_t Bits(float x) { return F32Bits(x); }
inline int32_t S32(uint64_t v) { return (int32_t)(uint32_t)v; }

// DXIL FMin / FMax: IEEE-754 2008 minNum / maxNum (a NaN operand loses).
float MinNum(float a, float b) {
  if (a != a) return b;
  if (b != b) return a;
  if (a == b) return Fl(Bits(a) | Bits(b)); // min(-0, +0) = -0
  return a < b ? a : b;
}
float MaxNum(float a, float b) {
  if (a != a) return b;
  if (b != b) return a;
  if (a == b) return Fl(Bits(a) & Bits(b)); // max(-0, +0) = +0
  return a > b ? a : b;
}
// Float -> int conversions saturate; NaN converts to 0 (D3D ftoi / ftou).
uint32_t FToI(float x) {
  if (x != x) return 0;
  if (x >= 2147483648.0f) return 0x7FFFFFFFu;
  if (x <= -2147483648.0f) return 0x80000000u;
  return (uint32_t)(int32_t)x;
}
uint32_t FToU(float x) {
  if (!(x > 0.0f)) return 0;
  if (x >= 4294967296.0f) return 0xFFFFFFFFu;
  return (uint32_t)x;
}
// Round to nearest even without the C runtime's rounding mode.
float RoundNe(float x) {
  const float ax = std::fabs(x);
  if (!(ax < 8388608.0f)) return x; // NaN, infinities, already integral
  float r = ax + 8388608.0f;
  r = r - 8388608.0f;
  return Fl(Bits(r) | (Bits(x) & 0x80000000u));
}
// f32 -> f16 (round to nearest even) and back, integer only.
uint32_t ToHalf(float x) {
  const uint32_t u = (uint32_t)Bits(x), sign = (u >> 16) & 0x8000u;
  const uint32_t e = (u >> 23) & 0xFF, m = u & 0x7FFFFFu;
  if (e == 0xFF) return sign | 0x7C00u | (m ? 0x200u : 0);
  int32_t he = (int32_t)e - 127 + 15;
  if (he >= 31) return sign | 0x7C00u;
  if (he <= 0) {
    if (he < -10) return sign;
    const uint32_t mm = m | 0x800000u, shift = (uint32_t)(14 - he);
    uint32_t h = mm >> shift;
    const uint32_t rem = mm & ((1u << shift) - 1), half = 1u << (shift - 1);
    if (rem > half || (rem == half && (h & 1))) ++h;
    return sign | h;
  }
  uint32_t h = ((uint32_t)he << 10) | (m >> 13);
  const uint32_t rem = m & 0x1FFFu;
  if (rem > 0x1000u || (rem == 0x1000u && (h & 1))) ++h; // may carry into the exponent
  return sign | h;
}
float FromHalf(uint32_t h) {
  const uint32_t sign = (h & 0x8000u) << 16, e = (h >> 10) & 0x1F, m = h & 0x3FFu;
  if (e == 0x1F) return Fl(sign | 0x7F800000u | (m << 13));
  if (e == 0) {
    if (m == 0) return Fl(sign);
    uint32_t mm = m, ee = 113;
    while (!(mm & 0x400u)) {
      mm <<= 1;
      --ee;
    }
    return Fl(sign | (ee << 23) | ((mm & 0x3FFu) << 13));
  }
  return Fl(sign | ((e + 112) << 23) | (m << 13));
}
uint32_t BitFieldExtract(uint32_t width, uint32_t offset, uint32_t v, bool sign) {
  width &= 31;
  offset &= 31;
  if (width == 0) return 0;
  if (width + offset < 32) {
    const uint32_t up = v << (32 - width - offset);
    return sign ? (uint32_t)(S32(up) >> (32 - width)) : up >> (32 - width);
  }
  return sign ? (uint32_t)(S32(v) >> offset) : v >> offset;
}
uint32_t BitReverse(uint32_t v) {
  v = ((v >> 1) & 0x55555555u) | ((v & 0x55555555u) << 1);
  v = ((v >> 2) & 0x33333333u) | ((v & 0x33333333u) << 2);
  v = ((v >> 4) & 0x0F0F0F0Fu) | ((v & 0x0F0F0F0Fu) << 4);
  v = ((v >> 8) & 0x00FF00FFu) | ((v & 0x00FF00FFu) << 8);
  return (v >> 16) | (v << 16);
}

// Exact compile-time evaluation; false for operations that are not folded.
bool Eval(uint32_t op, uint32_t srcTy, uint32_t dstTy, uint64_t a, uint64_t b, uint64_t c, uint64_t &out) {
  const uint32_t ua = (uint32_t)a, ub = (uint32_t)b, uc = (uint32_t)c;
  const float fa = Fl(a), fb = Fl(b), fc = Fl(c);
  uint64_t r;
  switch (op) {
  case kIAdd: r = ua + ub; break;
  case kISub: r = ua - ub; break;
  case kIMul: r = ua * ub; break;
  case kUDiv: r = ub ? ua / ub : 0xFFFFFFFFu; break;
  case kURem: r = ub ? ua % ub : 0xFFFFFFFFu; break;
  case kSDiv: r = ub == 0 ? 0xFFFFFFFFu : (ua == 0x80000000u && ub == 0xFFFFFFFFu) ? ua : (uint32_t)(S32(a) / S32(b)); break;
  case kSRem: r = ub == 0 ? 0xFFFFFFFFu : (ua == 0x80000000u && ub == 0xFFFFFFFFu) ? 0 : (uint32_t)(S32(a) % S32(b)); break;
  case kShl: r = ua << (ub & 31); break;
  case kLShr: r = ua >> (ub & 31); break;
  case kAShr: r = (uint32_t)(S32(a) >> (ub & 31)); break;
  case kAnd: r = ua & ub; break;
  case kOr: r = ua | ub; break;
  case kXor: r = ua ^ ub; break;
  case kFAdd: r = Bits(fa + fb); break;
  case kFSub: r = Bits(fa - fb); break;
  case kFMul: r = Bits(fa * fb); break;
  case kFDiv: r = Bits(fa / fb); break;
  case kICmpEq: r = ua == ub; break;
  case kICmpNe: r = ua != ub; break;
  case kICmpUgt: r = ua > ub; break;
  case kICmpUge: r = ua >= ub; break;
  case kICmpUlt: r = ua < ub; break;
  case kICmpUle: r = ua <= ub; break;
  case kICmpSgt: r = S32(a) > S32(b); break;
  case kICmpSge: r = S32(a) >= S32(b); break;
  case kICmpSlt: r = S32(a) < S32(b); break;
  case kICmpSle: r = S32(a) <= S32(b); break;
  case kFCmpOeq: r = fa == fb; break;
  case kFCmpOgt: r = fa > fb; break;
  case kFCmpOge: r = fa >= fb; break;
  case kFCmpOlt: r = fa < fb; break;
  case kFCmpOle: r = fa <= fb; break;
  case kFCmpOne: r = fa < fb || fa > fb; break;
  case kFCmpOrd: r = fa == fa && fb == fb; break;
  case kFCmpUno: r = fa != fa || fb != fb; break;
  case kFCmpUeq: r = !(fa < fb || fa > fb); break;
  case kFCmpUne: r = !(fa == fb); break;
  case kTrunc: r = dstTy == kI1 ? ua & 1 : ua; break;
  case kZExt: r = srcTy == kI1 ? ua & 1 : ua; break;
  case kSExt: r = srcTy == kI1 ? ((ua & 1) ? 0xFFFFFFFFu : 0) : ua; break;
  case kFPToUI: r = FToU(fa); break;
  case kFPToSI: r = FToI(fa); break;
  case kUIToFP: r = Bits((float)ua); break;
  case kSIToFP: r = Bits((float)S32(a)); break;
  case kFPTrunc: r = ToHalf(fa); break;
  case kFPExt: r = Bits(FromHalf(ua & 0xFFFFu)); break;
  case kBitcast: r = ua; break;
  case kSelect: r = (uc & 1) ? a : b; break;
  case kFAbs: r = ua & 0x7FFFFFFFu; break;
  case kFNeg: r = ua ^ 0x80000000u; break;
  case kSaturate: r = Bits(fa != fa ? 0.0f : MinNum(MaxNum(fa, 0.0f), 1.0f)); break;
  case kIsNaN: r = fa != fa; break;
  case kIsInf: r = (ua & 0x7FFFFFFFu) == 0x7F800000u; break;
  case kFrc: { const float fl = std::floor(fa); r = Bits(fa - fl); break; }
  case kSqrt: r = Bits(std::sqrt(fa)); break;
  case kRsqrt: { const float s = std::sqrt(fa); r = Bits(1.0f / s); break; }
  case kRcp: r = Bits(1.0f / fa); break;
  case kRoundNe: r = Bits(RoundNe(fa)); break;
  case kRoundNi: r = Bits(std::floor(fa)); break;
  case kRoundPi: r = Bits(std::ceil(fa)); break;
  case kRoundZ: r = Bits(std::trunc(fa)); break;
  case kBfrev: r = BitReverse(ua); break;
  case kCountbits: r = (uint32_t)std::popcount(ua); break;
  case kFirstbitLo: r = ua ? (uint32_t)std::countr_zero(ua) : 0xFFFFFFFFu; break;
  case kFirstbitHi: r = ua ? 31u - (uint32_t)std::countl_zero(ua) : 0xFFFFFFFFu; break;
  case kFMax: r = Bits(MaxNum(fa, fb)); break;
  case kFMin: r = Bits(MinNum(fa, fb)); break;
  case kIMax: r = S32(a) > S32(b) ? ua : ub; break;
  case kIMin: r = S32(a) < S32(b) ? ua : ub; break;
  case kUMax: r = ua > ub ? ua : ub; break;
  case kUMin: r = ua < ub ? ua : ub; break;
  case kFMad: { const float m = fa * fb; r = Bits(m + fc); break; }
  case kIMad: case kUMad: r = ua * ub + uc; break;
  case kIbfe: r = BitFieldExtract(ua, ub, uc, true); break;
  case kUbfe: r = BitFieldExtract(ua, ub, uc, false); break;
  case kUMulHi: r = (uint32_t)(((uint64_t)ua * ub) >> 32); break;
  case kIMulHi: r = (uint32_t)(((int64_t)S32(a) * S32(b)) >> 32); break;
  default: return false;
  }
  if (dstTy == kI1) r &= 1;
  out = r & 0xFFFFFFFFull;
  return true;
}

inline bool IsC(const Fn &f, uint32_t v) { return v != kNone && IsConst(f.nodes[v]); }
inline uint32_t CU(const Fn &f, uint32_t v) { return (uint32_t)f.nodes[v].val; }
inline bool IsCI(const Fn &f, uint32_t v, uint32_t x) { return IsC(f, v) && CU(f, v) == x; }
inline bool IsCF(const Fn &f, uint32_t v, float x) { return IsC(f, v) && CU(f, v) == (uint32_t)Bits(x); }
inline bool IsPow2(uint32_t x) { return x && !(x & (x - 1)); }

// Known bits (zero / one masks) of an integer value.
struct KnownBits {
  uint32_t zero, one;
};
KnownBits Known(const Fn &f, uint32_t v) {
  const Node &n = f.nodes[v];
  if (IsConst(n)) return {~(uint32_t)n.val, (uint32_t)n.val};
  return {(uint32_t)n.val, (uint32_t)(n.val >> 32)};
}
uint64_t FloatFacts(const Fn &f, uint32_t v) {
  const Node &n = f.nodes[v];
  if (!IsConst(n)) return n.val;
  const float x = Fl(n.val);
  uint64_t r = 0;
  if (x == x) r |= kNotNaN;
  if (!(x < 0.0f)) r |= kNonNeg;
  if (!(x > 1.0f)) r |= kLe1;
  if (!(n.val & 0x80000000u)) r |= kSignClear;
  if (x == x && std::floor(x) == x) r |= kIntegral;
  return r;
}
inline uint64_t PackKnown(uint32_t zero, uint32_t one) { return zero | ((uint64_t)one << 32); }

// Facts of node i from its operands' facts (sound; phis meet their inputs).
template <uint32_t R = 0> uint64_t ComputeFactsOf(const Fn &f, uint32_t i) { // per replica via Visit
  const Node &n = f.nodes[i];
  if (IsPhi(n)) {
    if (IsFloatTy(n.type)) return FloatFacts(f, n.a) & FloatFacts(f, n.b);
    const KnownBits x = Known(f, n.a), y = Known(f, n.b);
    return PackKnown(x.zero & y.zero, x.one & y.one);
  }
  const uint32_t op = OpOf(n);
  if (n.type == kI1) return PackKnown(~1u, 0);
  if (IsFloatTy(n.type)) {
    switch (op) {
    case kSaturate: return kNotNaN | kNonNeg | kLe1;
    case kFAbs: return (FloatFacts(f, n.a) & kNotNaN) | kNonNeg | kSignClear;
    case kFrc: return kNonNeg | kLe1;
    case kSqrt: case kRsqrt: case kExp: return kNonNeg;
    case kFMul:
      if (n.a == n.b) return kNonNeg;
      [[fallthrough]];
    case kFAdd: {
      const uint64_t x = FloatFacts(f, n.a), y = FloatFacts(f, n.b);
      uint64_t r = x & y & kNonNeg;
      if (op == kFMul && (x & y & kNonNeg) && (x & y & kLe1)) r |= kLe1;
      return r;
    }
    case kFMax: return (FloatFacts(f, n.a) | FloatFacts(f, n.b)) & kNonNeg;
    case kFMin: return (FloatFacts(f, n.a) | FloatFacts(f, n.b)) & kLe1;
    case kSelect: return FloatFacts(f, n.a) & FloatFacts(f, n.b);
    case kRoundNe: case kRoundNi: case kRoundPi: case kRoundZ:
      return kIntegral | (FloatFacts(f, n.a) & (kNotNaN | kNonNeg));
    case kSIToFP: return kNotNaN | kIntegral;
    case kUIToFP: return kNotNaN | kIntegral | kNonNeg | kSignClear;
    default: return 0;
    }
  }
  if (n.type != kI32) return 0;
  switch (op) {
  case kAnd: { const KnownBits x = Known(f, n.a), y = Known(f, n.b); return PackKnown(x.zero | y.zero, x.one & y.one); }
  case kOr: { const KnownBits x = Known(f, n.a), y = Known(f, n.b); return PackKnown(x.zero & y.zero, x.one | y.one); }
  case kXor: {
    const KnownBits x = Known(f, n.a), y = Known(f, n.b);
    return PackKnown((x.zero & y.zero) | (x.one & y.one), (x.zero & y.one) | (x.one & y.zero));
  }
  case kShl:
    if (IsC(f, n.b)) {
      const uint32_t s = CU(f, n.b) & 31;
      const KnownBits x = Known(f, n.a);
      return PackKnown((x.zero << s) | ((1u << s) - 1), x.one << s);
    }
    return 0;
  case kLShr:
    if (IsC(f, n.b)) {
      const uint32_t s = CU(f, n.b) & 31;
      const KnownBits x = Known(f, n.a);
      return PackKnown((x.zero >> s) | ~(0xFFFFFFFFu >> s), x.one >> s);
    }
    return 0;
  case kZExt: return PackKnown(~1u, 0);
  case kUbfe:
    if (IsC(f, n.a)) {
      const uint32_t w = CU(f, n.a) & 31;
      return w ? PackKnown(~((1u << w) - 1), 0) : PackKnown(~0u, 0);
    }
    return 0;
  case kCountbits: return PackKnown(~63u, 0);
  case kUMin: {
    const KnownBits x = Known(f, n.a), y = Known(f, n.b);
    const uint32_t hx = 0xFFFFFFFFu >> std::countl_zero(~x.zero | 1), hy = 0xFFFFFFFFu >> std::countl_zero(~y.zero | 1);
    return PackKnown(~(hx < hy ? hx : hy), 0);
  }
  case kURem:
    if (IsC(f, n.b) && CU(f, n.b)) return PackKnown(~(0xFFFFFFFFu >> std::countl_zero(CU(f, n.b) - 1 | 1)), 0);
    return 0;
  case kSelect: { const KnownBits x = Known(f, n.a), y = Known(f, n.b); return PackKnown(x.zero & y.zero, x.one & y.one); }
  default: return 0;
  }
}

// Rewrites node i in place into op(a, b, c) (operands re-linked).
void Rewrite(Fn &f, uint32_t i, uint32_t op, uint32_t a, uint32_t b = kNone, uint32_t c = kNone) {
  DropOperands(f, i);
  Node &n = f.nodes[i];
  n.op = (n.op & ~kOpMask) | op;
  n.a = a;
  n.b = b;
  n.c = c;
  for (uint32_t k = 0; k < Arity(op); ++k) AddUse(f, i, k, Operand(n, k));
  f.st.peepholes++;
}
inline bool Repl(Fn &f, uint32_t i, uint32_t to) {
  f.st.peepholes++;
  Replace(f, i, to);
  return true;
}
inline bool ToConst(Fn &f, uint32_t i, uint64_t bits) {
  f.st.peepholes++;
  MakeConst(f, i, bits);
  return true;
}
// A uniqued constant operand for a rewrite (kNone when no slot is left).
inline uint32_t C32(Fn &f, uint32_t v) { return GetConst(f, kI32, v); }

// Algebraic rules of one opcode (instantiated per opcode, like InstCombine's
// visitXxx / nir_opt_algebraic's generated per-opcode matchers). Returns true
// when the node was replaced, folded or rewritten.
template <uint32_t Op, uint32_t R> NOINLINE bool Visit(Fn &f, uint32_t i) {
  SIMV5_REPLICA_TAG(R); // one copy per code replica (WorkloadRealisticV5Replica.h)
  Node &n = f.nodes[i];
  const uint32_t a = n.a, b = n.b;
  f.st.combined++;
  if constexpr (IsCommutative(Op)) {
    if (IsC(f, a) && !IsC(f, b)) { // canonical: constant right
      SwapOperands(f, i);
      return Visit<Op, R>(f, i);
    }
  }
  if constexpr (Op == kIAdd || Op == kOr || Op == kXor || Op == kShl || Op == kLShr || Op == kAShr || Op == kISub) {
    if (IsCI(f, b, 0) || ((Op == kShl || Op == kLShr || Op == kAShr) && IsC(f, b) && (CU(f, b) & 31) == 0))
      return Repl(f, i, a); // x op 0
  }
  if constexpr (Op == kISub || Op == kXor) {
    if (a == b) return ToConst(f, i, 0);
  }
  if constexpr (Op == kAnd || Op == kOr) {
    if (a == b) return Repl(f, i, a);
  }
  if constexpr (Op == kIMul) {
    if (IsCI(f, b, 0)) return ToConst(f, i, 0);
    if (IsCI(f, b, 1)) return Repl(f, i, a);
    if (IsC(f, b) && IsPow2(CU(f, b))) { // strength reduction
      const uint32_t s = C32(f, (uint32_t)std::countr_zero(CU(f, b)));
      if (s != kNone) {
        Rewrite(f, i, kShl, a, s);
        return true;
      }
    }
  }
  if constexpr (Op == kAnd) {
    if (n.type == kI1) {
      if (IsCI(f, b, 1)) return Repl(f, i, a);
      if (IsCI(f, b, 0)) return ToConst(f, i, 0);
    } else if (IsC(f, b)) {
      const KnownBits x = Known(f, a);
      const uint32_t m = CU(f, b);
      if ((m | x.zero) == 0xFFFFFFFFu) return Repl(f, i, a); // mask keeps every possibly-set bit
      if ((m & ~x.zero) == 0) return ToConst(f, i, 0);      // every kept bit is known zero
    }
  }
  if constexpr (Op == kOr) {
    if (n.type == kI1 && IsCI(f, b, 1)) return ToConst(f, i, 1);
    if (n.type == kI32 && IsCI(f, b, 0xFFFFFFFFu)) return ToConst(f, i, 0xFFFFFFFFu);
  }
  if constexpr (Op == kXor) {
    const Node &x = f.nodes[a]; // not(not(b)) on booleans
    if (n.type == kI1 && IsCI(f, b, 1) && IsInst(x) && OpOf(x) == kXor && IsCI(f, x.b, 1)) return Repl(f, i, x.a);
  }
  if constexpr (Op == kLShr) {
    const Node &x = f.nodes[a]; // (x << c) >> c -> x & mask
    if (IsC(f, b) && IsInst(x) && OpOf(x) == kShl && x.b == b && x.numUses == 1) {
      const uint32_t m = C32(f, 0xFFFFFFFFu >> (CU(f, b) & 31));
      if (m != kNone) {
        Rewrite(f, i, kAnd, x.a, m);
        return true;
      }
    }
  }
  if constexpr (Op == kUDiv || Op == kURem) {
    if (IsCI(f, b, 1)) return Op == kUDiv ? Repl(f, i, a) : ToConst(f, i, 0);
    if (IsC(f, b) && IsPow2(CU(f, b))) {
      const uint32_t k = Op == kUDiv ? C32(f, (uint32_t)std::countr_zero(CU(f, b))) : C32(f, CU(f, b) - 1);
      if (k != kNone) {
        Rewrite(f, i, Op == kUDiv ? kLShr : kAnd, a, k);
        return true;
      }
    }
  }
  if constexpr (Op == kUMin || Op == kUMax || Op == kIMin || Op == kIMax || Op == kFMin || Op == kFMax) {
    if (a == b) return Repl(f, i, a);
  }
  if constexpr (Op == kUMin) {
    if (IsC(f, b)) { // x already below the bound (known leading zeros)
      const uint32_t maxX = ~Known(f, a).zero;
      if (maxX <= CU(f, b)) return Repl(f, i, a);
    }
  }
  if constexpr (Op == kFAdd || Op == kFSub) {
    if (IsCF(f, b, 0.0f) || IsCF(f, b, -0.0f)) return Repl(f, i, a);
    if (Op == kFSub && a == b) return ToConst(f, i, Bits(0.0f));
  }
  if constexpr (Op == kFMul) {
    if (IsCF(f, b, 1.0f)) return Repl(f, i, a);
    if (IsCF(f, b, 0.0f)) return ToConst(f, i, Bits(0.0f)); // not "precise": NaN/Inf ignored, as drivers do
    if (IsCF(f, b, -1.0f)) {
      Rewrite(f, i, kFNeg, a);
      return true;
    }
  }
  if constexpr (Op == kFDiv) {
    if (IsCF(f, b, 1.0f)) return Repl(f, i, a);
  }
  if constexpr (Op == kFMad) {
    const uint32_t c = n.c;
    if (IsCF(f, b, 0.0f)) return Repl(f, i, c);
    if (IsCF(f, b, 1.0f)) {
      Rewrite(f, i, kFAdd, a, c);
      return true;
    }
    if (IsCF(f, c, 0.0f)) {
      Rewrite(f, i, kFMul, a, b);
      return true;
    }
  }
  if constexpr (Op == kFNeg) {
    const Node &x = f.nodes[a];
    if (IsInst(x) && OpOf(x) == kFNeg) return Repl(f, i, x.a);
  }
  if constexpr (Op == kFAbs) {
    const Node &x = f.nodes[a];
    if (FloatFacts(f, a) & kSignClear) return Repl(f, i, a);
    if (IsInst(x) && (OpOf(x) == kFNeg || OpOf(x) == kFAbs)) {
      SetOperand(f, i, 0, x.a); // fabs(-x), fabs(fabs(x)) -> fabs(x)
      f.st.peepholes++;
      return true;
    }
  }
  if constexpr (Op == kSaturate) {
    const uint64_t r = FloatFacts(f, a);
    if ((r & (kNotNaN | kNonNeg | kLe1)) == (kNotNaN | kNonNeg | kLe1)) return Repl(f, i, a);
  }
  if constexpr (Op == kFMax) {
    if (IsCF(f, b, 0.0f) && (FloatFacts(f, a) & (kNotNaN | kNonNeg)) == (kNotNaN | kNonNeg)) return Repl(f, i, a);
  }
  if constexpr (Op == kFMin) {
    if (IsCF(f, b, 1.0f) && (FloatFacts(f, a) & (kNotNaN | kLe1)) == (kNotNaN | kLe1)) return Repl(f, i, a);
  }
  if constexpr (Op == kRoundNe || Op == kRoundNi || Op == kRoundPi || Op == kRoundZ) {
    if (FloatFacts(f, a) & kIntegral) return Repl(f, i, a);
  }
  if constexpr (Op == kIsNaN) {
    if (FloatFacts(f, a) & kNotNaN) return ToConst(f, i, 0);
  }
  if constexpr (Op == kICmpEq || Op == kICmpUle || Op == kICmpUge || Op == kICmpSle || Op == kICmpSge) {
    if (a == b) return ToConst(f, i, 1);
  }
  if constexpr (Op == kICmpNe || Op == kICmpUlt || Op == kICmpUgt || Op == kICmpSlt || Op == kICmpSgt) {
    if (a == b) return ToConst(f, i, 0);
  }
  if constexpr (Op == kICmpUlt || Op == kICmpUge) {
    if (IsC(f, b)) {
      if (CU(f, b) == 0) return ToConst(f, i, Op == kICmpUge);
      if (~Known(f, a).zero < CU(f, b)) return ToConst(f, i, Op == kICmpUlt); // range from known bits
    }
  }
  if constexpr (Op == kICmpNe || Op == kICmpEq) {
    if (IsC(f, b) && (CU(f, b) & Known(f, a).zero) != 0) return ToConst(f, i, Op == kICmpNe); // impossible value
  }
  if constexpr (Op == kFCmpOrd || Op == kFCmpUno) {
    if ((FloatFacts(f, a) & FloatFacts(f, b) & kNotNaN) != 0) return ToConst(f, i, Op == kFCmpOrd);
  }
  if constexpr (Op == kFCmpOlt) {
    if (IsCF(f, b, 0.0f) && (FloatFacts(f, a) & kNonNeg)) return ToConst(f, i, 0);
  }
  if constexpr (Op == kFCmpOge) {
    if (IsCF(f, b, 0.0f) && (FloatFacts(f, a) & (kNonNeg | kNotNaN)) == (kNonNeg | kNotNaN)) return ToConst(f, i, 1);
  }
  if constexpr (Op == kSelect) {
    const uint32_t c = n.c;
    if (IsC(f, c)) return Repl(f, i, (CU(f, c) & 1) ? a : b);
    if (a == b) return Repl(f, i, a);
    if (n.type == kI1 && IsCI(f, a, 1) && IsCI(f, b, 0)) return Repl(f, i, c);
    if (n.type == kI32 && IsCI(f, a, 1) && IsCI(f, b, 0)) { // select(c, 1, 0) -> zext(c)
      Rewrite(f, i, kZExt, c);
      return true;
    }
  }
  if constexpr (Op == kBitcast || Op == kTrunc) {
    const Node &x = f.nodes[a]; // bitcast(bitcast(v)) / trunc(zext(b)) round trips
    if (IsInst(x) && OpOf(x) == (Op == kBitcast ? kBitcast : kZExt) && f.nodes[x.a].type == n.type) return Repl(f, i, x.a);
  }
  if constexpr (Op == kExtract) { // extract from a constant-free aggregate: nothing to fold
    (void)a;
  }
  n.val = ComputeFactsOf<R>(f, i);
  return false;
}

using VisitFn = bool (*)(Fn &, uint32_t);
template <uint32_t R, uint32_t... I>
constexpr std::array<VisitFn, sizeof...(I)> VisitTable(std::integer_sequence<uint32_t, I...>) {
  return {{&Visit<I, R>...}};
}
template <uint32_t... R>
constexpr std::array<std::array<VisitFn, kOpCount>, sizeof...(R)> VisitTables(std::integer_sequence<uint32_t, R...>) {
  return {{VisitTable<R>(std::make_integer_sequence<uint32_t, kOpCount>{})...}};
}
constexpr auto kVisit = VisitTables(std::make_integer_sequence<uint32_t, kReplicas>{}); // [replica][op]

// phi(x, x), phi(x, self) -> x; phi of equal constants -> constant.
bool RemovePhi(Fn &f, uint32_t i) {
  const Node &n = f.nodes[i];
  const uint32_t other = n.b == i ? n.a : n.a == i ? n.b : n.a == n.b ? n.a : kNone;
  if (other != kNone) {
    f.st.peepholes++;
    Replace(f, i, other);
    return true;
  }
  if (IsC(f, n.a) && IsC(f, n.b) && CU(f, n.a) == CU(f, n.b)) return ToConst(f, i, f.nodes[n.a].val);
  f.nodes[i].val = ComputeFactsOf(f, i);
  return false;
}

// Late source modifiers live in Node::imm of ALU instructions (extract index
// and memory offsets use the field differently).
inline bool HasModifiers(const Node &n) {
  return n.imm && OpOf(n) != kExtract && !HasFlag(OpOf(n), kMemRead | kSide);
}
template <class Body> inline bool Walk(Fn &f, Body &&body) {
  bool progress = false;
  for (uint32_t k = 0; k < f.nrpo; ++k) {
    const uint32_t b = f.rpoOrder[k];
    for (uint32_t i = f.blocks[b].head; i != kNone;) {
      const uint32_t next = f.nodes[i].next;
      progress |= body(i);
      i = next;
    }
  }
  return progress;
}
} // namespace

// nir_opt_constant_folding: instructions whose operands are all constants.
bool OptConstantFolding(Fn &f) {
  return Walk(f, [&](uint32_t i) {
    const Node &n = f.nodes[i];
    if (!IsInst(n) || HasFlag(OpOf(n), kNoFold) || HasModifiers(n)) return false;
    const uint32_t ar = Arity(OpOf(n));
    if (ar == 0 || !IsC(f, n.a) || (ar > 1 && !IsC(f, n.b)) || (ar > 2 && !IsC(f, n.c))) return false;
    uint64_t out;
    const uint64_t va = f.nodes[n.a].val, vb = ar > 1 ? f.nodes[n.b].val : 0, vc = ar > 2 ? f.nodes[n.c].val : 0;
    if (!Eval(OpOf(n), f.nodes[n.a].type, n.type, va, vb, vc, out)) return false;
    f.st.folded++;
    MakeConst(f, i, out);
    return true;
  });
}

// nir_opt_algebraic (+ trivially dead instructions, nir_opt_remove_phis).
bool OptAlgebraic(Fn &f) {
  return Walk(f, [&](uint32_t i) {
    const Node &n = f.nodes[i];
    if (n.op & (kConstFlag | kDeadFlag)) return false;
    if (n.numUses == 0 && !(n.op & kCondFlag) && !IsStore(n)) { // no uses, no side effect
#ifdef SIMV5_DEAD_TRACE
      if (f.diag) std::fprintf(stderr, "deadop alg %u%c", IsPhi(n) ? 999u : OpOf(n), 10);
#endif
      EraseNode(f, i);
      f.st.dead++;
      return true;
    }
    if (IsPhi(n)) return RemovePhi(f, i);
    if (HasModifiers(n)) return false; // source modifiers: selected code, not IR algebra
    return kVisit[ReplicaOf(n.block)][OpOf(n)](f, i);
  });
}

void ComputeFacts(Fn &f, uint32_t i) { f.nodes[i].val = ComputeFactsOf(f, i); }

// --- Node creation and constant uniquing ------------------------------------
uint32_t NewNode(Fn &f, uint32_t op, uint32_t type, uint32_t a, uint32_t b, uint32_t c) {
  uint32_t i;
  if (f.freeList != kNone) {
    i = f.freeList;
    f.freeList = f.nodes[i].a;
    f.st.slotsReused++;
  } else if (f.n < f.cap) {
    i = f.n++;
  } else {
    f.st.slotsExhausted++;
    return kNone;
  }
  Node &n = f.nodes[i];
  n.op = op;
  n.a = a;
  n.b = b;
  n.c = c;
  n.firstUse = kNone;
  n.reg = kNoReg;
  n.val = 0;
  n.numUses = 0;
  n.type = type;
  n.block = 0;
  n.prev = n.next = kNone;
  n.name = n.liveIdx = n.pos = kNone;
  n.imm = 0;
  for (uint32_t k = 0, e = NumOperands(n); k < e; ++k) AddUse(f, i, k, Operand(n, k));
  return i;
}

namespace {
inline uint64_t ConstKey(uint32_t type, uint64_t bits) { return ((uint64_t)type << 32) | (uint32_t)bits; }
uint32_t *Find(DenseMap &m, uint64_t key, bool &found) {
  for (uint32_t s = (uint32_t)Mix(key) & (m.size - 1);; s = (s + 1) & (m.size - 1)) {
    if (m.keys[s] == key) {
      found = true;
      return &m.vals[s];
    }
    if (m.keys[s] == DenseMap::kEmpty) {
      found = false;
      m.keys[s] = key;
      return &m.vals[s];
    }
  }
}
// Grows (rehashes) the table when it would exceed 3/4 load.
bool Reserve(Fn &f, DenseMap &m) {
  if (m.size && (m.count + 1) * 4 <= m.size * 3) return true;
  const uint32_t size = m.size ? m.size * 2 : 64;
  DenseMap g;
  g.keys = f.ar->Take<uint64_t>(size);
  g.vals = f.ar->Take<uint32_t>(size);
  if (!g.keys || !g.vals) return false;
  g.size = size;
  for (uint32_t s = 0; s < size; ++s) g.keys[s] = DenseMap::kEmpty;
  for (uint32_t s = 0; s < m.size; ++s) {
    if (m.keys[s] == DenseMap::kEmpty) continue;
    bool found;
    *Find(g, m.keys[s], found) = m.vals[s];
    g.count++;
  }
  f.st.mapRehashes++;
  m = g;
  return true;
}
} // namespace

bool MapConst(Fn &f, uint32_t node) {
  if (!Reserve(f, f.consts)) return false;
  bool found;
  uint32_t *slot = Find(f.consts, ConstKey(f.nodes[node].type, f.nodes[node].val), found);
  if (found) return false;
  *slot = node;
  f.consts.count++;
  return true;
}

uint32_t GetConst(Fn &f, uint32_t type, uint64_t bits) {
  if (!Reserve(f, f.consts)) return kNone;
  bool found;
  const uint64_t key = ConstKey(type, bits);
  uint32_t *slot = Find(f.consts, key, found);
  if (found) return *slot;
  const uint32_t node = NewNode(f, kConstFlag | kNotAnOp, type, kNone, kNone, kNone);
  if (node == kNone) { // undo the reserved slot: rebuild without it
    f.consts.keys[slot - f.consts.vals] = DenseMap::kEmpty;
    return kNone;
  }
  f.nodes[node].val = (uint32_t)bits;
  *slot = node;
  f.consts.count++;
  return node;
}
} // namespace simv5
