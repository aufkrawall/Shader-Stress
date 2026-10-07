// WorkloadRealisticV5.h - Internals shared by the realistic V5 shader-compiler
// model (WorkloadRealisticV5*.cpp). Not part of the workload API: callers use
// RunRealisticCompilerSim_V5 / RunRealisticCompilerSimV5Diag (Workloads.h).
//
// V5 models what a GPU driver does with a DXIL shader (an LLVM-bitcode module):
//  Corpus  - a process-wide, deterministic set of shaders encoded as LLVM-style
//            bitstreams (abbreviations, VBR operands, relative value ids,
//            constants / function / value-symbol-table blocks); like a game's
//            shader set, each one is compiled many times for pipeline variants
//            (specialization constants from the pipeline-state key).
//  Front   - bitstream reader (BitstreamCursor-style, generic record reader)
//            and IR construction: 128-byte instruction objects with
//            co-allocated, doubly linked operand uses and per-block
//            instruction lists, phis, branches; name interning.
//  Lower   - NIR-style lowering pipeline: 48 generated filtered passes over
//            the instruction lists (half before, half after the optimization
//            loop), divergence analysis, gather_info, IR validation (diag).
//  Opt     - generated per-opcode combine handlers (like nir_opt_algebraic or
//            InstCombine, erasing trivially dead instructions), dead control
//            flow, dominator tree (Cooper-Harvey-Kennedy), scoped
//            dominator-tree CSE (EarlyCSE), dead-code elimination.
//  Back    - dense-bitset block liveness (NIR-style iterative dataflow), live
//            ranges, per-block list scheduling on a dependence DAG with a
//            critical-path priority queue, linear-scan register allocation,
//            per-opcode encoders (scalar encodings for uniform values, a
//            gather_info header), and a hash of the binary for the shader cache.
// Power design (5700X, ledger P062-P064): real-sized IR objects and many
// streaming instruction-list passes are what lift package power to the
// 115-120 W target; both mirror production GPU compilers.
// Integer only, no unordered containers or unstable sorts: results are
// bit-identical across compilers (required by paired cross-core verification).
#pragma once
#include "core/Common.h"
#include "workloads/Workloads.h"
#include <bit>
#include <cstdint>
#include <cstring>

namespace simv5 {
constexpr uint32_t kOps = 256;           // opcodes = distinct handlers per table
constexpr uint32_t kNone = 0xFFFFFFFFu;
constexpr uint32_t kConstFlag = 0x80000000u;
constexpr uint32_t kDeadFlag = 0x40000000u;
constexpr uint32_t kPhiFlag = 0x20000000u;
constexpr uint32_t kCondFlag = 0x10000000u;  // used by a terminator (branch / return)
constexpr uint32_t kInputFlag = 0x08000000u; // input / resource load (never folded)
constexpr uint32_t kDivergentFlag = 0x04000000u; // varies per lane (divergence analysis)
constexpr uint32_t kOpMask = 0xFFFFu;
constexpr uint32_t kRegs = 63;           // allocatable registers (GPU-like file)
constexpr uint32_t kNoReg = 0xFD;        // stores and constants
constexpr uint32_t kSpill = 0xFE;
constexpr uint32_t kSpecConsts = 8;      // specialization constants per shader
constexpr uint32_t kMaxSucc = 2;

constexpr uint64_t Mix(uint64_t z) {
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
constexpr uint64_t OpConst(uint32_t op, uint32_t k) {
  return Mix((uint64_t)op * 0x9E3779B97F4A7C15ull + (uint64_t)k * 0xD1B54A32D192ED03ull);
}
inline uint64_t Next(uint64_t &s) { return Mix(s += 0x9E3779B97F4A7C15ull); }
constexpr uint32_t Family(uint32_t op) { return op & 7; }
constexpr bool IsStoreOp(uint32_t op) { return (op & 15) == 15; }
constexpr uint32_t Arity(uint32_t op) {
  return IsStoreOp(op) ? 2 : Family(op) == 3 ? 3 : 1 + ((op >> 3) & 1);
}
constexpr bool IsCommutative(uint32_t op) {
  return Arity(op) == 2 && !IsStoreOp(op) && (Family(op) == 0 || Family(op) == 1 || Family(op) == 6);
}

// One IR instruction, laid out like an LLVM Instruction with co-allocated
// operand Uses (or a NIR instr with embedded sources): hot fields first, then
// the operand use links, then parent / list / analysis bookkeeping. Nodes come
// from a 128-byte allocator size class (mimalloc / jemalloc bin), so every
// node owns two cache lines; passes stream through real-sized IR (P062).
struct Node {
  uint32_t op;          // opcode | kConstFlag | kDeadFlag | kPhiFlag | ...
  uint32_t a, b, c;     // operand node indices (kNone when unused); phi: a, b
  uint32_t firstUse;    // use-list head (use id = user * 4 + operand slot)
  uint32_t reg;         // register, kSpill or kNoReg
  uint64_t val;         // constant value or analysis summary
  uint32_t useNext[3];  // operand slot k: next use of the same value
  uint32_t usePrev[3];  // operand slot k: previous use (kNone at the head)
  uint32_t numUses;     // length of the use list (use_empty() checks)
  uint32_t type;        // result type id from the bitstream (0: void)
  uint32_t block;       // parent block
  uint32_t prev, next;  // instruction list (program order, later schedule order)
  uint32_t name;        // interned symbol-table slot (kNone: unnamed)
  uint32_t liveIdx;     // dense liveness index (kNone: not tracked)
  uint32_t pos;         // schedule position
  uint8_t slack[128 - 88]; // allocator size-class tail (never accessed)
};
static_assert(sizeof(Node) == 128, "IR nodes use the 128-byte size class");
inline bool IsConst(const Node &n) { return (n.op & kConstFlag) != 0; }
inline bool IsDead(const Node &n) { return (n.op & kDeadFlag) != 0; }
inline bool IsPhi(const Node &n) { return (n.op & kPhiFlag) != 0; }
inline bool IsInput(const Node &n) { return (n.op & kInputFlag) != 0; }
inline bool IsStore(const Node &n) { return !(n.op & (kInputFlag | kPhiFlag | kConstFlag)) && IsStoreOp(n.op & kOpMask); }
inline uint32_t Operand(const Node &n, uint32_t k) { return k == 0 ? n.a : k == 1 ? n.b : n.c; }
inline uint32_t &OperandRef(Node &n, uint32_t k) { return k == 0 ? n.a : k == 1 ? n.b : n.c; }
inline uint32_t UseOf(uint32_t user, uint32_t k) { return user * 4 + k; }
inline uint32_t UseUser(uint32_t u) { return u >> 2; }

struct Block {
  uint32_t first, last;        // node range [first, last); phis first
  uint32_t succ[kMaxSucc];     // kNone when absent
  uint32_t cond;               // branch condition node (kNone: unconditional)
  uint32_t idom;               // immediate dominator (entry: itself)
  uint32_t rpo;                // reverse post-order index
  uint32_t domChild, domSibling; // dominator tree (kNone terminated)
  uint32_t predFirst, npred;   // into Fn::preds
  uint32_t head;               // first instruction of the list (kNone: empty)
};

struct Arena {
  uint8_t *base;
  size_t used, cap;
  template <class T> T *Take(size_t count) {
    used = (used + 63) & ~size_t(63);
    T *p = reinterpret_cast<T *>(base + used);
    used += count * sizeof(T);
    return used <= cap ? p : nullptr;
  }
};

// Shader summary for the binary header and driver state (gather_info).
struct ShaderInfo {
  uint32_t famCount[8];    // ALU instructions per opcode family
  uint64_t inputsRead;     // input slots read (mod 64)
  uint32_t stores, phis, uniform, divergent;
};

// One function being compiled (all storage in the per-thread arena).
struct Fn {
  Node *nodes = nullptr;
  uint32_t n = 0, nconst = 0;
  Block *blocks = nullptr;
  uint32_t nblocks = 0;
  uint32_t *preds = nullptr;   // predecessor lists
  uint32_t *phiPred = nullptr; // phi node -> predecessor block of operand a
  uint32_t ret = kNone;        // returned value
  uint32_t *rpoOrder = nullptr; // reachable blocks in reverse post-order
  uint32_t nrpo = 0;
  uint32_t *stack = nullptr;   // worklist (deduplicated by inList)
  uint32_t sp = 0;
  uint64_t *inList = nullptr;
  uint64_t names = 0;          // checksum of the interned symbol table
  bool diag = false;           // collect diagnostics-only statistics
  // Liveness (Node::liveIdx dense indices): per-block live-in / live-out bitsets.
  uint32_t liveCount = 0, liveWords = 0;
  uint64_t *liveIn = nullptr, *liveOut = nullptr;
  // Schedule (Node::pos positions): node order, block -> first position.
  uint32_t *order = nullptr, *blockStart = nullptr;
  uint32_t norder = 0;
  uint32_t *rangeEnd = nullptr; // live-range end per live index
  ShaderInfo info;              // nir_shader_gather_info result (binary header)
  SimV5Diag st;
  uint32_t &UseNext(uint32_t u) { return nodes[UseUser(u)].useNext[u & 3]; }
  uint32_t &UsePrev(uint32_t u) { return nodes[UseUser(u)].usePrev[u & 3]; }
};

// Use lists (doubly linked through the users' operand slots).
inline void AddUse(Fn &f, uint32_t user, uint32_t k, uint32_t v) {
  Node &d = f.nodes[v];
  const uint32_t u = UseOf(user, k);
  f.nodes[user].useNext[k] = d.firstUse;
  f.nodes[user].usePrev[k] = kNone;
  if (d.firstUse != kNone) f.UsePrev(d.firstUse) = u;
  d.firstUse = u;
  d.numUses++;
}
inline void RemoveUse(Fn &f, uint32_t u, uint32_t v) {
  const uint32_t prev = f.UsePrev(u), next = f.UseNext(u);
  if (prev == kNone) f.nodes[v].firstUse = next;
  else f.UseNext(prev) = next;
  if (next != kNone) f.UsePrev(next) = prev;
  f.nodes[v].numUses--;
}
// Commutative operand swap (LLVM swapOperands): the uses move with the slots.
inline void SwapOperands(Fn &f, uint32_t i) {
  Node &n = f.nodes[i];
  const uint32_t a = n.a, b = n.b;
  RemoveUse(f, UseOf(i, 0), a);
  RemoveUse(f, UseOf(i, 1), b);
  n.a = b;
  n.b = a;
  AddUse(f, i, 0, b);
  AddUse(f, i, 1, a);
}
inline uint32_t NumOperands(const Node &n) {
  return IsConst(n) || IsInput(n) ? 0 : IsPhi(n) ? 2 : Arity(n.op & kOpMask);
}
// The node stops using its operands (before it becomes a constant or dies).
inline void DropOperands(Fn &f, uint32_t i) {
  const Node &n = f.nodes[i];
  for (uint32_t k = 0, e = NumOperands(n); k < e; ++k) RemoveUse(f, UseOf(i, k), Operand(n, k));
}
// Remove a node from its block's instruction list (no-op when not listed).
inline void Unlink(Fn &f, uint32_t i) {
  Node &n = f.nodes[i];
  if (n.prev != kNone) f.nodes[n.prev].next = n.next;
  else if (f.blocks[n.block].head == i) f.blocks[n.block].head = n.next;
  if (n.next != kNone) f.nodes[n.next].prev = n.prev;
  n.prev = n.next = kNone;
}
// Erase an instruction (LLVM eraseFromParent): drop its operand uses, unlink
// it from the instruction list and mark it dead. Remaining uses can only come
// from instructions that die in the same sweep.
inline void EraseNode(Fn &f, uint32_t i) {
  DropOperands(f, i);
  Unlink(f, i);
  f.nodes[i].op |= kDeadFlag;
}


// --- Corpus ------------------------------------------------------------------
struct ShaderRef {
  uint32_t wordOffset;         // start of the bitstream (32-bit words)
  uint32_t words;
  uint32_t values, blocks, consts; // sizes for arena planning
};
struct Corpus {
  const uint32_t *words;
  const ShaderRef *shaders;
  uint32_t classes, perClass;  // shaders[c * perClass + k]: class c is 512 << c values
};
const Corpus &GetCorpus();
constexpr uint32_t ClassValues(uint32_t c) { return 512u << c; }

// --- Phases ------------------------------------------------------------------
// Front: decodes `s` into `f`; spec[] replaces specialization constants.
bool ReadShader(const Corpus &corpus, const ShaderRef &s, const uint64_t *spec, Arena &ar, Fn &f);
// Opt
void RebuildPreds(Fn &f);    // predecessor lists (block order) from the successor edges
void RunCombine(Fn &f);
void PushAll(Fn &f);
bool RunDeadCf(Fn &f, Arena &ar);
void BuildDominators(Fn &f, Arena &ar);
void RunCse(Fn &f, Arena &ar);
void RunDce(Fn &f, Arena &ar);
// Lower (NIR-style lowering pipeline, WorkloadRealisticV5Lower.cpp)
void RunLowering(Fn &f, uint32_t firstPass, uint32_t endPass); // filtered instruction passes
void RunDivergence(Fn &f);   // uniform / divergent values (needs dominators)
void GatherInfo(Fn &f);
uint32_t ValidateIr(const Fn &f); // number of use-list / instruction-list inconsistencies
// Back
void RunLiveness(Fn &f, Arena &ar);
void Schedule(Fn &f, Arena &ar);
void BuildRanges(Fn &f, Arena &ar);
void RunRegAlloc(Fn &f, Arena &ar);
uint64_t EmitAndHash(Fn &f, Arena &ar);
} // namespace simv5
