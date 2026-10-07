// WorkloadRealisticV5.h - Internals shared by the realistic V5 shader-compiler
// model (WorkloadRealisticV5*.cpp). Not part of the workload API: callers use
// RunRealisticCompilerSim_V5 / RunRealisticCompilerSimV5Diag (Workloads.h).
//
// V5 models what a GPU driver does with DXIL shaders (LLVM-bitcode modules):
//  Corpus  - a process-wide, deterministic set of thousands of typed shaders
//            (pixel / compute) encoded as LLVM-style bitstreams; every compile
//            picks a shader and a pipeline state (state constants), like a
//            game's shader-cache build.
//  Front   - bitstream reader (abbreviations, VBR, relative value ids, generic
//            record reader), DXIL record decoding (binop / cast / cmp / select
//            / extractvalue / dx.op calls via their opcode constants) into
//            128-byte instruction objects with co-allocated, doubly linked
//            operand uses and per-block instruction lists.
//  Lower   - NIR-style lowering passes with real rewrite rules (descriptor and
//            memory lowering, division by constants, fdiv, interpolation,
//            ffma fusion, load vectorization, ...), divergence analysis,
//            gather_info, IR validation (diag).
//  Opt     - exact constant folding and algebraic simplification with known
//            bits / float range analysis (WorkloadRealisticV5Fold.cpp), dead
//            control flow, dominators (Cooper-Harvey-Kennedy), scoped EarlyCSE,
//            dead-code elimination.
//  Back    - list scheduling (IR), instruction selection to GFX9-like machine
//            code (WorkloadRealisticV5Isel.cpp), machine liveness and linear-scan
//            register allocation, phi / parallel-copy lowering (..Ra.cpp),
//            s_waitcnt insertion and real binary encodings (..Asm.cpp), and a
//            hash of the binary (shader cache key).
// Power design (5700X, ledger P062-P064): real-sized IR objects and many
// streaming instruction-list passes keep package power high; both mirror
// production GPU compilers.
// Results are bit-identical across compilers (paired cross-core verification):
// integer and strict IEEE single-operation float folding only, no libm.
#pragma once
#include "core/Common.h"
#include "workloads/WorkloadRealisticV5Ops.h"
#include "workloads/Workloads.h"
#include <bit>
#include <cstdint>
#include <cstring>

namespace simv5 {
constexpr uint32_t kOps = 256;           // opcode space (handler tables)
constexpr uint32_t kNone = 0xFFFFFFFFu;
constexpr uint32_t kConstFlag = 0x80000000u;
constexpr uint32_t kDeadFlag = 0x40000000u;
constexpr uint32_t kPhiFlag = 0x20000000u;
constexpr uint32_t kCondFlag = 0x10000000u;      // used by a terminator (branch condition)
constexpr uint32_t kDivergentFlag = 0x04000000u; // varies per lane (divergence analysis)
constexpr uint32_t kOpMask = 0xFFFFu;
constexpr uint32_t kNotAnOp = kOpCount;  // op bits of constants, phis and free slots
constexpr uint32_t kRegs = 63;           // allocatable registers (GPU-like file)
constexpr uint32_t kNoReg = 0xFD;        // stores and constants
constexpr uint32_t kSpill = 0xFE;
constexpr uint32_t kSpecConsts = 8;      // pipeline-state constants per shader
constexpr uint32_t kMaxSucc = 2;
static_assert(kOpCount < kOps, "opcode table");

constexpr uint64_t Mix(uint64_t z) {
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
constexpr uint64_t OpConst(uint32_t op, uint32_t k) {
  return Mix((uint64_t)op * 0x9E3779B97F4A7C15ull + (uint64_t)k * 0xD1B54A32D192ED03ull);
}
inline uint64_t Next(uint64_t &s) { return Mix(s += 0x9E3779B97F4A7C15ull); }
constexpr uint32_t UnitOf(uint32_t op) { return Info(op).unit; }
constexpr bool IsStoreOp(uint32_t op) { return HasFlag(op, kSide); }
constexpr uint32_t Arity(uint32_t op) { return Info(op).arity; }
constexpr bool IsCommutative(uint32_t op) { return HasFlag(op, kComm); }

// One IR instruction, laid out like an LLVM Instruction with co-allocated
// operand Uses (or a NIR instr with embedded sources): hot fields first, then
// the operand use links, then parent / list / analysis bookkeeping. Nodes come
// from a 128-byte allocator size class (mimalloc / jemalloc bin), so every
// node owns two cache lines; passes stream through real-sized IR (P062).
struct Node {
  uint32_t op;          // Op | kConstFlag | kDeadFlag | kPhiFlag | ...
  uint32_t a, b, c;     // operand node indices (kNone when unused); phi: a, b
  uint32_t firstUse;    // use-list head (use id = user * 4 + operand slot)
  uint32_t reg;         // register, kSpill or kNoReg
  uint64_t val;         // constant bits, or analysis facts (known bits / float range)
  uint32_t useNext[3];  // operand slot k: next use of the same value
  uint32_t usePrev[3];  // operand slot k: previous use (kNone at the head)
  uint32_t numUses;     // length of the use list (use_empty() checks)
  uint32_t type;        // result type (Ty)
  uint32_t block;       // parent block
  uint32_t prev, next;  // instruction list (program order, later schedule order)
  uint32_t name;        // interned symbol-table slot (kNone: unnamed)
  uint32_t liveIdx;     // dense liveness index (kNone: not tracked)
  uint32_t pos;         // schedule position
  uint32_t imm;         // literal operand (extractvalue index)
  uint8_t slack[128 - 92]; // allocator size-class tail (never accessed)
};
static_assert(sizeof(Node) == 128, "IR nodes use the 128-byte size class");
inline uint32_t OpOf(const Node &n) { return n.op & kOpMask; }
inline bool IsConst(const Node &n) { return (n.op & kConstFlag) != 0; }
inline bool IsDead(const Node &n) { return (n.op & kDeadFlag) != 0; }
inline bool IsPhi(const Node &n) { return (n.op & kPhiFlag) != 0; }
inline bool IsInst(const Node &n) { return !(n.op & (kConstFlag | kPhiFlag)); }
inline bool IsStore(const Node &n) { return IsInst(n) && IsStoreOp(OpOf(n)); }
inline bool IsMemRead(const Node &n) { return IsInst(n) && HasFlag(OpOf(n), kMemRead); }
inline uint32_t Operand(const Node &n, uint32_t k) { return k == 0 ? n.a : k == 1 ? n.b : n.c; }
inline uint32_t &OperandRef(Node &n, uint32_t k) { return k == 0 ? n.a : k == 1 ? n.b : n.c; }
inline uint32_t UseOf(uint32_t user, uint32_t k) { return user * 4 + k; }
inline uint32_t UseUser(uint32_t u) { return u >> 2; }
inline float AsF32(uint64_t bits) {
  float x;
  const uint32_t w = (uint32_t)bits;
  std::memcpy(&x, &w, 4);
  return x;
}
inline uint64_t F32Bits(float x) {
  uint32_t w;
  std::memcpy(&w, &x, 4);
  return w;
}

struct Block {
  uint32_t first, last;        // node range [first, last) as read; phis first
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

// Open-addressing hash map from 64-bit keys to node indices, grown by
// rehashing at 3/4 load like LLVM's DenseMap (constant uniquing).
struct DenseMap {
  static constexpr uint64_t kEmpty = ~0ull;
  uint64_t *keys = nullptr;
  uint32_t *vals = nullptr;
  uint32_t size = 0, count = 0;
};

// Shader summary for the binary header and driver state (gather_info).
struct ShaderInfo {
  uint32_t unitCount[8];   // instructions per execution unit class
  uint64_t inputsRead;     // input signature elements read (mod 64)
  uint32_t stores, phis, uniform, divergent;
};

// One function being compiled (all storage in the per-thread arena).
struct Fn {
  Node *nodes = nullptr;
  uint32_t n = 0, cap = 0;     // node slots in use (high water) / allocated
  uint32_t freeList = kNone;   // erased node slots for reuse (chained through Node::a)
  uint32_t nconst = 0;
  Block *blocks = nullptr;
  uint32_t nblocks = 0;
  uint32_t *preds = nullptr;   // predecessor lists
  uint32_t *phiPred = nullptr; // phi node -> predecessor block of operand a
  uint32_t ret = kNone;        // unused (DXIL entry points return void)
  uint32_t *rpoOrder = nullptr; // reachable blocks in reverse post-order
  uint32_t nrpo = 0;
  uint32_t *stack = nullptr;   // worklist (deduplicated by inList)
  uint32_t sp = 0;
  uint64_t *inList = nullptr;
  uint64_t names = 0;          // checksum of the interned symbol table
  bool diag = false;           // collect diagnostics-only statistics
  Arena *ar = nullptr;         // per-function allocator
  DenseMap consts;             // (type, bits) -> constant node
  // Instruction vectors (Linearize): per-block positions in list order.
  uint32_t *seq = nullptr, *seqStart = nullptr;
  uint32_t nseq = 0;
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
// Operand k now refers to v (LLVM Use::set).
inline void SetOperand(Fn &f, uint32_t i, uint32_t k, uint32_t v) {
  uint32_t &slot = OperandRef(f.nodes[i], k);
  if (slot == v) return;
  RemoveUse(f, UseOf(i, k), slot);
  slot = v;
  AddUse(f, i, k, v);
}
inline uint32_t NumOperands(const Node &n) {
  return IsConst(n) ? 0 : IsPhi(n) ? 2 : Arity(OpOf(n));
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
// Insert node i into the instruction list right before `before`.
inline void InsertBefore(Fn &f, uint32_t i, uint32_t before) {
  Node &n = f.nodes[i], &b = f.nodes[before];
  n.block = b.block;
  n.prev = b.prev;
  n.next = before;
  if (b.prev != kNone) f.nodes[b.prev].next = i;
  else f.blocks[b.block].head = i;
  b.prev = i;
}
// Erase an instruction (LLVM eraseFromParent): drop its operand uses, unlink
// it from the instruction list and mark it dead. Remaining uses can only come
// from instructions that die in the same sweep; a slot without uses goes back
// to the free list, so later allocations reuse it (allocator-like locality).
inline void EraseNode(Fn &f, uint32_t i) {
  DropOperands(f, i);
  Unlink(f, i);
  Node &n = f.nodes[i];
  n.op |= kDeadFlag;
  if (n.numUses == 0 && !(n.op & kCondFlag)) {
    n.op = kDeadFlag | kNotAnOp; // plain free slot: no operands
    n.a = f.freeList;
    n.b = n.c = kNone;
    f.freeList = i;
  }
}
// Node creation (Front / Lower / Opt). NewNode returns kNone when the slot
// budget is exhausted; callers then skip the transformation (deterministic).
// The new node is not in any instruction list yet (see InsertBefore).
uint32_t NewNode(Fn &f, uint32_t op, uint32_t type, uint32_t a, uint32_t b, uint32_t c);
uint32_t GetConst(Fn &f, uint32_t type, uint64_t bits); // uniqued constant (kNone: no slot)
bool MapConst(Fn &f, uint32_t node);                     // register an existing constant

// --- Corpus ------------------------------------------------------------------
struct ShaderRef {
  uint32_t wordOffset;         // start of the bitstream (32-bit words)
  uint32_t words;
  uint32_t values, blocks, consts; // sizes for arena planning
  uint32_t unused;                 // instruction values without a use (expected ~0)
};
struct Corpus {
  const uint32_t *words;
  const ShaderRef *shaders;
  uint32_t classes;            // class c: shaders of about 512 << c IR nodes
  const uint32_t *classFirst, *classCount; // shaders[classFirst[c] + k], k < classCount[c]
  uint32_t total;
};
const Corpus &GetCorpus();
constexpr uint32_t ClassValues(uint32_t c) { return 512u << c; }

// --- Phases ------------------------------------------------------------------
// Front: decodes `s` into `f`; spec[] supplies the pipeline-state constants.
bool ReadShader(const Corpus &corpus, const ShaderRef &s, const uint64_t *spec, Arena &ar, Fn &f);
// Fold (WorkloadRealisticV5Fold.cpp)
bool OptConstantFolding(Fn &f); // all-constant operands, one walk; progress
bool OptAlgebraic(Fn &f);    // algebraic rules + trivially dead code, one walk; progress
void ComputeFacts(Fn &f, uint32_t i); // known bits / float range of node i into val
// Opt
void RebuildPreds(Fn &f);    // predecessor lists (block order) from the successor edges
bool RunDeadCf(Fn &f, Arena &ar);
void BuildDominators(Fn &f, Arena &ar);
bool RunCse(Fn &f, Arena &ar);
bool RunDce(Fn &f, Arena &ar);
void Replace(Fn &f, uint32_t from, uint32_t to); // RAUW + erase
void MakeConst(Fn &f, uint32_t i, uint64_t bits); // node becomes a constant
// Lower (WorkloadRealisticV5Lower.cpp)
void RunEarlyLowering(Fn &f);
void RunLateLowering(Fn &f);
void RunDivergence(Fn &f);   // uniform / divergent values (needs dominators)
void GatherInfo(Fn &f);
uint32_t ValidateIr(const Fn &f); // number of use-list / instruction-list inconsistencies
// Back (machine code: WorkloadRealisticV5Mach.h)
void Linearize(Fn &f, Arena &ar);
void Schedule(Fn &f, Arena &ar);
} // namespace simv5
