// WorkloadRealisticV5Format.h - LLVM-bitstream constants of the V5 shader
// corpus (writer: WorkloadRealisticV5Corpus.cpp, reader: ...V5Front.cpp).
// Ids follow LLVM's bitcode where one exists (DXIL is LLVM 3.7 bitcode).
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
// Record codes.
constexpr uint32_t kDeclareBlocks = 1, kInstBinop = 2, kInstCast = 3, kInstRet = 10,
                   kInstBr = 11, kInstPhi = 16, kInstVSelect = 29, kInstCall = 34,
                   kInstLoad = 20, kInstStore = 44;
constexpr uint32_t kCstSetType = 1, kCstInteger = 4, kCstSpec = 25;
constexpr uint32_t kVstEntry = 1;
constexpr uint32_t kTypeI32 = 2, kTypeI64 = 3, kTypeDxOp = 7;
constexpr uint32_t kCallExplicitType = 0x8000;
constexpr uint32_t kDxOpFunction = 1; // callee value id offset of @dx.op.*
constexpr uint32_t kMaxAbbrevs = 8, kMaxAbbrevOps = 6;
} // namespace simv5::fmt
