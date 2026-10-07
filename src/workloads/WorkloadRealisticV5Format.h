// WorkloadRealisticV5Format.h - LLVM-bitstream constants of the V5 shader
// corpus (writer: WorkloadRealisticV5Corpus.cpp, reader: ...V5Front.cpp).
// Ids follow LLVM's bitcode where one exists (DXIL is LLVM 3.7 bitcode); type
// ids are the module type table (simv5::Ty), dx.op numbers live in V5Ops.h.
#pragma once
#include <cstdint>

namespace simv5::fmt {
// Builtin abbreviation ids.
constexpr uint32_t kEndBlock = 0, kEnterSubblock = 1, kDefineAbbrev = 2, kUnabbrevRecord = 3;
constexpr uint32_t kAbbrevFirst = 4; // first application-defined abbreviation
// Abbreviation operand encodings (literal is a separate flag bit in the stream).
enum AbbrevKind : uint32_t { kLiteral = 0, kFixed = 1, kVbr = 2, kArray = 3, kChar6 = 4 };
struct AbbrevOp {
  AbbrevKind kind;
  uint32_t value; // literal value or field width
};
// Abbreviation id widths per block.
constexpr unsigned kTopWidth = 2, kFnWidth = 4, kCstWidth = 4, kVstWidth = 4;
// Block ids.
constexpr uint32_t kConstantsBlock = 11, kFunctionBlock = 12, kValueSymtabBlock = 14;
// Function block record codes (LLVM FUNC_CODE_*).
constexpr uint32_t kDeclareBlocks = 1, kInstBinop = 2, kInstCast = 3, kInstRet = 10,
                   kInstBr = 11, kInstPhi = 16, kInstExtractVal = 26, kInstCmp2 = 28,
                   kInstVSelect = 29, kInstCall = 34;
// Constants block record codes (LLVM CST_CODE_*; 25 = pipeline-state constant,
// patched by the driver per pipeline variant).
constexpr uint32_t kCstSetType = 1, kCstInteger = 4, kCstFloat = 6, kCstSpec = 25;
constexpr uint32_t kVstEntry = 1;
constexpr uint32_t kTypeDxOpFn = 8;          // function type of @dx.op.* declarations
constexpr uint32_t kCallExplicitType = 0x8000;
// Callee of a dx.op call: relative id `id + kDxOpCallee + overload type` (the
// declaration @dx.op.<class>.<overload> in the module's global value list).
constexpr uint32_t kDxOpCallee = 1;
constexpr uint32_t kMaxAbbrevs = 8, kMaxAbbrevOps = 6;
} // namespace simv5::fmt
