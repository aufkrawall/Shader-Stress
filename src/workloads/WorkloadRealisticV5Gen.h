// WorkloadRealisticV5Gen.h - Realistic V5 corpus internals shared by the
// shader generator (WorkloadRealisticV5Corpus.cpp) and the bitstream encoder /
// corpus storage (WorkloadRealisticV5Encode.cpp): a generated shader is a typed
// SSA program (constants, instructions, labels) before encoding.
#pragma once
#include "workloads/WorkloadRealisticV5.h"
#include <vector>

namespace simv5 {
// Unique shaders per size class (512 << c values): many small, few large; the
// job driver picks class c with probability 2^-(c+1).
constexpr uint32_t kClasses = 6;
constexpr uint32_t kClassShaders[kClasses] = {2048, 1024, 512, 256, 128, 128};

enum Kind : uint8_t { kInst, kPhi, kBr, kBrCond, kRet };
struct WInst {
  Kind kind;
  uint8_t op = 0, ty = kVoid, imm = 0; // ty: result type (casts: destination; calls: overload)
  uint32_t a = kNone, b = kNone, c = kNone; // value ids; br: c = condition
  uint32_t t = kNone, f = kNone;            // labels (br, phi preds)
};
struct ConstDef {
  uint8_t ty;
  int8_t spec; // pipeline-state constant index, or -1
  uint32_t bits;
};
struct Program {
  std::vector<ConstDef> consts;
  std::vector<WInst> insts;
  std::vector<uint32_t> labels; // label -> block index
  uint32_t nconst = 0, nblocks = 0;
  uint32_t unused = 0;          // instruction values without a use (expected ~0)
  uint32_t dxop[kOpCount] = {}; // dx.op opcode constant id per op
  uint64_t nameSeed = 0;        // symbol-table names
};
void GenerateShader(uint64_t seed, uint32_t values, Program &out);
} // namespace simv5
