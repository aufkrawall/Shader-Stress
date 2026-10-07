// WorkloadRealisticV5Ops.h - IR opcode table of the realistic V5 compiler
// model: the DXIL subset a driver sees (LLVM 3.7 instructions plus dx.op
// intrinsics, with their bitcode record codes and DXIL opcode numbers) and the
// driver-internal operations created by lowering. Semantics are real: folding
// (WorkloadRealisticV5Fold.cpp) evaluates them exactly.
#pragma once
#include <cstdint>

namespace simv5 {
// Value types (ids of the module type table; LLVM-style numbering).
enum Ty : uint8_t {
  kVoid = 0, kI1 = 1, kI32 = 2, kI64 = 3, kF32 = 4, kF16 = 5, kHandle = 6,
  kResRetF32 = 7, kResRetI32 = 9, kTyCount = 10,
  kTySame = 0xFE,     // result type = type of operand a
  kTyExplicit = 0xFF, // result type comes from the record (casts, extracts)
};
inline constexpr bool IsFloatTy(uint32_t t) { return t == kF32 || t == kF16; }
inline constexpr bool IsResRet(uint32_t t) { return t == kResRetF32 || t == kResRetI32; }

// Execution unit class: latency model, instruction selection, gather_info.
enum Unit : uint8_t { kUnitInt, kUnitFloat, kUnitTrans, kUnitCmp, kUnitCvt, kUnitMem, kUnitMisc, kUnitSide };
// Bitcode record kind that encodes the operation (kRecNone: driver-internal).
enum Rec : uint8_t { kRecBinop, kRecCast, kRecCmp, kRecSelect, kRecExtract, kRecCall, kRecNone };
enum OpFlags : uint16_t {
  kComm = 1,       // commutative in operands a, b
  kSide = 2,       // side effect (store / output): a DCE root, never CSE'd
  kMemRead = 4,    // reads memory or shader I/O (opaque to folding)
  kPure = 8,       // value depends only on its operands (CSE candidate)
  kDivSource = 16, // result varies per lane (divergence source)
  kNoFold = 32,    // not evaluated at compile time (transcendentals, I/O)
};

// X(name, arity, result type, unit, record kind, record code, latency, flags)
// record code: LLVM binop / cast opcode, cmp predicate, or DXIL dx.op number.
#define SIMV5_OPS(X)                                                                      \
  X(IAdd, 2, kTySame, kUnitInt, kRecBinop, 0, 1, kComm | kPure)                           \
  X(ISub, 2, kTySame, kUnitInt, kRecBinop, 1, 1, kPure)                                   \
  X(IMul, 2, kTySame, kUnitInt, kRecBinop, 2, 4, kComm | kPure)                           \
  X(UDiv, 2, kTySame, kUnitInt, kRecBinop, 3, 24, kPure)                                  \
  X(SDiv, 2, kTySame, kUnitInt, kRecBinop, 4, 28, kPure)                                  \
  X(URem, 2, kTySame, kUnitInt, kRecBinop, 5, 24, kPure)                                  \
  X(SRem, 2, kTySame, kUnitInt, kRecBinop, 6, 28, kPure)                                  \
  X(Shl, 2, kTySame, kUnitInt, kRecBinop, 7, 1, kPure)                                    \
  X(LShr, 2, kTySame, kUnitInt, kRecBinop, 8, 1, kPure)                                   \
  X(AShr, 2, kTySame, kUnitInt, kRecBinop, 9, 1, kPure)                                   \
  X(And, 2, kTySame, kUnitInt, kRecBinop, 10, 1, kComm | kPure)                           \
  X(Or, 2, kTySame, kUnitInt, kRecBinop, 11, 1, kComm | kPure)                            \
  X(Xor, 2, kTySame, kUnitInt, kRecBinop, 12, 1, kComm | kPure)                           \
  X(FAdd, 2, kTySame, kUnitFloat, kRecBinop, 0, 1, kComm | kPure)                         \
  X(FSub, 2, kTySame, kUnitFloat, kRecBinop, 1, 1, kPure)                                 \
  X(FMul, 2, kTySame, kUnitFloat, kRecBinop, 2, 1, kComm | kPure)                         \
  X(FDiv, 2, kTySame, kUnitFloat, kRecBinop, 4, 10, kPure)                                \
  X(ICmpEq, 2, kI1, kUnitCmp, kRecCmp, 32, 1, kComm | kPure)                              \
  X(ICmpNe, 2, kI1, kUnitCmp, kRecCmp, 33, 1, kComm | kPure)                              \
  X(ICmpUgt, 2, kI1, kUnitCmp, kRecCmp, 34, 1, kPure)                                     \
  X(ICmpUge, 2, kI1, kUnitCmp, kRecCmp, 35, 1, kPure)                                     \
  X(ICmpUlt, 2, kI1, kUnitCmp, kRecCmp, 36, 1, kPure)                                     \
  X(ICmpUle, 2, kI1, kUnitCmp, kRecCmp, 37, 1, kPure)                                     \
  X(ICmpSgt, 2, kI1, kUnitCmp, kRecCmp, 38, 1, kPure)                                     \
  X(ICmpSge, 2, kI1, kUnitCmp, kRecCmp, 39, 1, kPure)                                     \
  X(ICmpSlt, 2, kI1, kUnitCmp, kRecCmp, 40, 1, kPure)                                     \
  X(ICmpSle, 2, kI1, kUnitCmp, kRecCmp, 41, 1, kPure)                                     \
  X(FCmpOeq, 2, kI1, kUnitCmp, kRecCmp, 1, 1, kComm | kPure)                              \
  X(FCmpOgt, 2, kI1, kUnitCmp, kRecCmp, 2, 1, kPure)                                      \
  X(FCmpOge, 2, kI1, kUnitCmp, kRecCmp, 3, 1, kPure)                                      \
  X(FCmpOlt, 2, kI1, kUnitCmp, kRecCmp, 4, 1, kPure)                                      \
  X(FCmpOle, 2, kI1, kUnitCmp, kRecCmp, 5, 1, kPure)                                      \
  X(FCmpOne, 2, kI1, kUnitCmp, kRecCmp, 6, 1, kComm | kPure)                              \
  X(FCmpOrd, 2, kI1, kUnitCmp, kRecCmp, 7, 1, kComm | kPure)                              \
  X(FCmpUno, 2, kI1, kUnitCmp, kRecCmp, 8, 1, kComm | kPure)                              \
  X(FCmpUeq, 2, kI1, kUnitCmp, kRecCmp, 9, 1, kComm | kPure)                              \
  X(FCmpUne, 2, kI1, kUnitCmp, kRecCmp, 14, 1, kComm | kPure)                             \
  X(Trunc, 1, kTyExplicit, kUnitCvt, kRecCast, 0, 1, kPure)                               \
  X(ZExt, 1, kTyExplicit, kUnitCvt, kRecCast, 1, 1, kPure)                                \
  X(SExt, 1, kTyExplicit, kUnitCvt, kRecCast, 2, 1, kPure)                                \
  X(FPToUI, 1, kTyExplicit, kUnitCvt, kRecCast, 3, 4, kPure)                              \
  X(FPToSI, 1, kTyExplicit, kUnitCvt, kRecCast, 4, 4, kPure)                              \
  X(UIToFP, 1, kTyExplicit, kUnitCvt, kRecCast, 5, 4, kPure)                              \
  X(SIToFP, 1, kTyExplicit, kUnitCvt, kRecCast, 6, 4, kPure)                              \
  X(FPTrunc, 1, kTyExplicit, kUnitCvt, kRecCast, 7, 4, kPure)                             \
  X(FPExt, 1, kTyExplicit, kUnitCvt, kRecCast, 8, 4, kPure)                               \
  X(Bitcast, 1, kTyExplicit, kUnitCvt, kRecCast, 11, 0, kPure)                            \
  X(Select, 3, kTySame, kUnitMisc, kRecSelect, 0, 1, kPure)                               \
  X(Extract, 1, kTyExplicit, kUnitMisc, kRecExtract, 0, 0, kPure)                         \
  X(FAbs, 1, kTySame, kUnitFloat, kRecCall, 6, 1, kPure)                                  \
  X(Saturate, 1, kTySame, kUnitFloat, kRecCall, 7, 1, kPure)                              \
  X(IsNaN, 1, kI1, kUnitCmp, kRecCall, 8, 1, kPure)                                       \
  X(IsInf, 1, kI1, kUnitCmp, kRecCall, 9, 1, kPure)                                       \
  X(Cos, 1, kTySame, kUnitTrans, kRecCall, 12, 16, kPure | kNoFold)                       \
  X(Sin, 1, kTySame, kUnitTrans, kRecCall, 13, 16, kPure | kNoFold)                       \
  X(Exp, 1, kTySame, kUnitTrans, kRecCall, 21, 4, kPure | kNoFold)                        \
  X(Frc, 1, kTySame, kUnitFloat, kRecCall, 22, 1, kPure)                                  \
  X(Log, 1, kTySame, kUnitTrans, kRecCall, 23, 4, kPure | kNoFold)                        \
  X(Sqrt, 1, kTySame, kUnitTrans, kRecCall, 24, 4, kPure)                                 \
  X(Rsqrt, 1, kTySame, kUnitTrans, kRecCall, 25, 4, kPure)                                \
  X(RoundNe, 1, kTySame, kUnitFloat, kRecCall, 26, 1, kPure)                              \
  X(RoundNi, 1, kTySame, kUnitFloat, kRecCall, 27, 1, kPure)                              \
  X(RoundPi, 1, kTySame, kUnitFloat, kRecCall, 28, 1, kPure)                              \
  X(RoundZ, 1, kTySame, kUnitFloat, kRecCall, 29, 1, kPure)                               \
  X(Bfrev, 1, kTySame, kUnitInt, kRecCall, 30, 1, kPure)                                  \
  X(Countbits, 1, kTySame, kUnitInt, kRecCall, 31, 1, kPure)                              \
  X(FirstbitLo, 1, kTySame, kUnitInt, kRecCall, 32, 1, kPure)                             \
  X(FirstbitHi, 1, kTySame, kUnitInt, kRecCall, 33, 1, kPure)                             \
  X(FMax, 2, kTySame, kUnitFloat, kRecCall, 35, 1, kComm | kPure)                         \
  X(FMin, 2, kTySame, kUnitFloat, kRecCall, 36, 1, kComm | kPure)                         \
  X(IMax, 2, kTySame, kUnitInt, kRecCall, 37, 1, kComm | kPure)                           \
  X(IMin, 2, kTySame, kUnitInt, kRecCall, 38, 1, kComm | kPure)                           \
  X(UMax, 2, kTySame, kUnitInt, kRecCall, 39, 1, kComm | kPure)                           \
  X(UMin, 2, kTySame, kUnitInt, kRecCall, 40, 1, kComm | kPure)                           \
  X(FMad, 3, kTySame, kUnitFloat, kRecCall, 46, 1, kPure)                                 \
  X(Fma, 3, kTySame, kUnitFloat, kRecCall, 47, 1, kPure | kNoFold)                        \
  X(IMad, 3, kTySame, kUnitInt, kRecCall, 48, 4, kPure)                                   \
  X(UMad, 3, kTySame, kUnitInt, kRecCall, 49, 4, kPure)                                   \
  X(Ibfe, 3, kTySame, kUnitInt, kRecCall, 51, 1, kPure)                                   \
  X(Ubfe, 3, kTySame, kUnitInt, kRecCall, 52, 1, kPure)                                   \
  X(LoadInput, 2, kF32, kUnitMem, kRecCall, 4, 8, kMemRead | kPure | kDivSource | kNoFold) \
  X(StoreOutput, 2, kVoid, kUnitSide, kRecCall, 5, 4, kSide | kNoFold)                    \
  X(CreateHandle, 2, kHandle, kUnitMisc, kRecCall, 57, 1, kPure | kNoFold)                \
  X(CBufferLoad, 2, kTyExplicit, kUnitMem, kRecCall, 59, 24, kMemRead | kPure | kNoFold)  \
  X(Sample, 3, kResRetF32, kUnitMem, kRecCall, 60, 64, kMemRead | kPure | kNoFold)        \
  X(TextureLoad, 3, kTyExplicit, kUnitMem, kRecCall, 66, 48, kMemRead | kPure | kNoFold)  \
  X(BufferLoad, 2, kTyExplicit, kUnitMem, kRecCall, 68, 48, kMemRead | kNoFold)           \
  X(BufferStore, 3, kVoid, kUnitSide, kRecCall, 69, 4, kSide | kNoFold)                   \
  X(ThreadId, 1, kI32, kUnitMisc, kRecCall, 93, 1, kPure | kDivSource | kNoFold)          \
  X(GroupId, 1, kI32, kUnitMisc, kRecCall, 94, 1, kPure | kNoFold)                        \
  X(FNeg, 1, kTySame, kUnitFloat, kRecNone, 0, 1, kPure)                                  \
  X(Rcp, 1, kTySame, kUnitTrans, kRecNone, 0, 4, kPure)                                   \
  X(UMulHi, 2, kTySame, kUnitInt, kRecNone, 0, 4, kComm | kPure)                          \
  X(IMulHi, 2, kTySame, kUnitInt, kRecNone, 0, 4, kComm | kPure)                          \
  X(DescLoad, 2, kHandle, kUnitMem, kRecNone, 0, 24, kMemRead | kPure | kNoFold)          \
  X(LoadUbo, 2, kTyExplicit, kUnitMem, kRecNone, 0, 24, kMemRead | kPure | kNoFold)       \
  X(LoadUboX4, 2, kResRetF32, kUnitMem, kRecNone, 0, 24, kMemRead | kPure | kNoFold)      \
  X(Interp, 2, kF32, kUnitMem, kRecNone, 0, 8, kMemRead | kPure | kDivSource | kNoFold)   \
  X(ImageSample, 3, kResRetF32, kUnitMem, kRecNone, 0, 64, kMemRead | kPure | kNoFold)    \
  X(ImageLoad, 3, kTyExplicit, kUnitMem, kRecNone, 0, 48, kMemRead | kPure | kNoFold)     \
  X(LoadSsbo, 2, kTyExplicit, kUnitMem, kRecNone, 0, 48, kMemRead | kNoFold)              \
  X(StoreSsbo, 3, kVoid, kUnitSide, kRecNone, 0, 4, kSide | kNoFold)                      \
  X(Export, 2, kVoid, kUnitSide, kRecNone, 0, 4, kSide | kNoFold)

enum Op : uint32_t {
#define SIMV5_ENUM(name, ar, ty, unit, rec, code, lat, flags) k##name,
  SIMV5_OPS(SIMV5_ENUM)
#undef SIMV5_ENUM
      kOpCount
};

struct OpInfo {
  uint8_t arity, ty, unit, rec, code, latency;
  uint16_t flags;
};
inline constexpr OpInfo kOpInfo[kOpCount + 1] = {
#define SIMV5_INFO(name, ar, ty, unit, rec, code, lat, flags) \
  {ar, ty, unit, rec, code, lat, (uint16_t)(flags)},
    SIMV5_OPS(SIMV5_INFO)
#undef SIMV5_INFO
    {0, kVoid, kUnitMisc, kRecNone, 0, 0, 0}};
inline constexpr const OpInfo &Info(uint32_t op) { return kOpInfo[op < kOpCount ? op : kOpCount]; }
inline constexpr bool HasFlag(uint32_t op, uint16_t f) { return (Info(op).flags & f) != 0; }

// Bitcode decoding tables (record code -> op).
inline constexpr uint32_t kNoOp = 0xFFFF;
struct CodeMaps {
  uint16_t intBinop[16], floatBinop[16], cast[16], cmp[64], dxop[128];
};
inline constexpr CodeMaps MakeCodeMaps() {
  CodeMaps m{};
  for (auto &v : m.intBinop) v = kNoOp;
  for (auto &v : m.floatBinop) v = kNoOp;
  for (auto &v : m.cast) v = kNoOp;
  for (auto &v : m.cmp) v = kNoOp;
  for (auto &v : m.dxop) v = kNoOp;
  for (uint32_t op = 0; op < kOpCount; ++op) {
    const OpInfo &i = kOpInfo[op];
    if (i.rec == kRecBinop) (i.unit == kUnitFloat ? m.floatBinop : m.intBinop)[i.code] = (uint16_t)op;
    else if (i.rec == kRecCast) m.cast[i.code] = (uint16_t)op;
    else if (i.rec == kRecCmp) m.cmp[i.code] = (uint16_t)op;
    else if (i.rec == kRecCall) m.dxop[i.code] = (uint16_t)op;
  }
  return m;
}
inline constexpr CodeMaps kCodeMaps = MakeCodeMaps();
} // namespace simv5
